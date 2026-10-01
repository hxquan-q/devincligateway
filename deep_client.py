#!/usr/bin/env python3
"""deep_client.py — 裸协议 Devin 推理客户端 (v2: 连接池 + 取消 + 错误透传)。

逆向还原的协议 (详见 timeline.md):
  auth  = Basic <windsurf_api_key>   # key 形如 "devin-session-token$<JWT>"
  rpc   = POST {api_server}/exa.api_server_pb.ApiServerService/GetChatMessage
  codec = application/connect+proto; 帧 = flag(1B)+len_be32(4B)+proto
  请求  {1:client_info, 3:messages{1:uuid,2:role,3:content}, 7:varint5, 21:model}
  响应帧 {3:答案增量, 9:思维链, 7:{2:prompt_tok,3:completion_tok,9:model}}
"""
import http.client
import json
import os
import queue
import re
import ssl
import struct
import threading
import time
import urllib.parse
import uuid

CHUNK = 16384

class DeepError(Exception):
    """服务端 RPC 错误 (code/message 来自 connect trailer)。"""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Cancelled(Exception):
    pass


# ---------------------------------------------------------------- 凭据缓存

_cred_cache = {"mtime": None, "key": None, "url": None}


def _cred_file_candidates():
    """跨平台 credentials.toml 搜索路径 (VPS/Linux 部署用)。"""
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA")
    xdg = os.environ.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share")
    cands = []
    if appdata:
        cands.append(os.path.join(appdata, "devin", "credentials.toml"))
    cands += [
        os.path.join(xdg, "devin", "credentials.toml"),
        os.path.join(home, ".config", "devin", "credentials.toml"),
        os.path.join(home, ".devin", "credentials.toml"),
    ]
    return cands


def read_credentials() -> tuple:
    """返回 (windsurf_api_key 含前缀, api_server_url 去尾斜杠)。

    优先级: 环境变量 DEVIN_API_KEY / DEVIN_API_SERVER_URL > credentials.toml
    (VPS 部署推荐用环境变量, 免装 devin CLI)
    """
    env_key = os.environ.get("DEVIN_API_KEY")
    env_url = os.environ.get("DEVIN_API_SERVER_URL")
    if env_key and env_url:
        return env_key, env_url.rstrip("/")
    path = next((p for p in _cred_file_candidates() if os.path.exists(p)), None)
    if path is None:
        raise RuntimeError(
            "no credentials: set DEVIN_API_KEY + DEVIN_API_SERVER_URL, "
            "or provide credentials.toml (Windows %APPDATA%\\devin\\, "
            "Linux ~/.local/share/devin/)")
    mtime = os.path.getmtime(path)
    if _cred_cache["mtime"] == mtime and _cred_cache["key"]:
        return _cred_cache["key"], _cred_cache["url"]
    txt = open(path, encoding="utf-8").read()
    key = re.search(r'windsurf_api_key\s*=\s*"([^"]+)"', txt).group(1)
    url = re.search(r'api_server_url\s*=\s*"([^"]+)"', txt).group(1).rstrip("/")
    _cred_cache.update(mtime=mtime, key=key, url=url)
    return key, url


_fp_lock = threading.Lock()
_fp_cache = None


def client_fingerprint() -> bytes:
    """field 31: 客户端指纹 (登录会话内静态, 内存缓存)。

    来源优先级: DEVIN_FP_HEX (hex 字符串) / DEVIN_FP_FILE > ci31.bin (脚本目录,
    ~/.devin/)。部署 VPS 时随包携带 ci31.bin 即可 (与 credentials 同一次登录提取)。
    """
    global _fp_cache
    if _fp_cache is not None:
        return _fp_cache
    with _fp_lock:
        if _fp_cache is not None:
            return _fp_cache
        hexenv = os.environ.get("DEVIN_FP_HEX")
        if hexenv:
            _fp_cache = bytes.fromhex(hexenv.strip())
            return _fp_cache
        fp_file = os.environ.get("DEVIN_FP_FILE")
        cands = [fp_file] if fp_file else []
        cands.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ci31.bin"))
        cands.append(os.path.expanduser("~/.devin/ci31.bin"))
        for p in cands:
            if p and os.path.exists(p):
                _fp_cache = open(p, "rb").read()
                return _fp_cache
        _fp_cache = b""
        return _fp_cache


# ---------------------------------------------------------------- 连接池

class ConnPool:
    """HTTPS keep-alive 连接池 (LIFO 复用热连接, 绕过环境代理)。"""

    def __init__(self, host: str, maxsize: int = 16):
        self.host = host
        self.maxsize = maxsize
        self._pool = queue.LifoQueue(maxsize=maxsize)
        self._ctx = ssl.create_default_context()

    def _new(self) -> http.client.HTTPSConnection:
        return http.client.HTTPSConnection(self.host, 443, context=self._ctx,
                                           timeout=300)

    def get(self):
        try:
            return self._pool.get_nowait()
        except queue.Empty:
            return self._new()

    def put(self, conn, broken: bool = False):
        if broken:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            return
        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            conn.close()


_pool_lock = threading.Lock()
_pool = None      # ConnPool
_pool_url = None


def _get_pool(base_url: str) -> ConnPool:
    global _pool, _pool_url
    if _pool is None or _pool_url != base_url:
        with _pool_lock:
            if _pool is None or _pool_url != base_url:
                host = urllib.parse.urlparse(base_url).hostname
                _pool = ConnPool(host)
                _pool_url = base_url
    return _pool


# ---------------------------------------------------------------- protobuf 编解码

def varint(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def field(fn: int, payload) -> bytes:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return varint(fn << 3 | 2) + varint(len(payload)) + payload


def field_varint(fn: int, v: int) -> bytes:
    return varint(fn << 3 | 0) + varint(v)


def field_f64(fn: int, v: float) -> bytes:
    return varint(fn << 3 | 1) + struct.pack("<d", v)


def wire_fields(data: bytes) -> dict:
    out = {}
    i = 0

    def vi(d, i):
        r = 0
        s = 0
        while True:
            b = d[i]
            i += 1
            r |= (b & 0x7F) << s
            if not b & 0x80:
                return r, i
            s += 7

    while i < len(data):
        try:
            key, i = vi(data, i)
        except IndexError:
            break
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = vi(data, i)
            out.setdefault(fn, []).append(v)
        elif wt == 2:
            ln, i = vi(data, i)
            out.setdefault(fn, []).append(data[i:i + ln])
            i += ln
        elif wt == 5:
            i += 4
        elif wt == 1:
            i += 8
        else:
            break
    return out


def build_request(messages: list, auth: str, model: str, fp: bytes = None,
                  tools: list = None, cfg: bytes = None) -> bytes:
    """messages: dict 列表 {uuid, role, content?, tool_call?{id,name,args_json}, term?}
    role: 1=user, 2=assistant(工具调用), 4=工具结果 (逆向确认)
    tools: [{name, description, input_schema}] → field10 {1,2,3:JSON串}
    """
    ver = "3000.11.3"
    ci = (field(1, b"chisel") + field(2, ver.encode()) + field(3, auth.encode())
          + field(4, b"en") + field(5, b"windows") + field(7, ver.encode())
          + field(12, b"chisel"))
    if fp is None:
        fp = client_fingerprint()
    if fp:
        ci += field(31, fp)
    body = field(1, ci)
    for m in messages:
        msg = field(1, str(m["uuid"]).encode()) + field_varint(2, m["role"])
        if m.get("content"):
            msg += field(3, str(m["content"]).encode())
        tc = m.get("tool_call")
        if tc:
            msg += field(6, field(1, tc["id"].encode())
                         + field(2, tc["name"].encode())
                         + field(3, tc["args_json"].encode()))
        if m.get("term") == 11:
            msg += field(11, b"")
        if m.get("term") == 7:
            msg += field(7, b"")
        body += field(3, msg)
    if tools:
        for t in tools:
            body += field(10, field(1, t["name"].encode())
                          + field(2, t["description"].encode())
                          + field(3, json.dumps(t.get("input_schema", {}))))
    if cfg:
        body += field(8, cfg)
    body += field_varint(7, 5)          # 必需: 来源枚举
    body += field(21, model.encode())   # 模型路由键
    return body


def build_completion_config(temperature=None, top_p=None, top_k=40, max_ctx=128000):
    """field 8 (逆向确认: f5/f8 为 f64 wiretype1; f3 非 max_output_tokens)。

    注意: 一旦附带 field 8, f8(top_p) 为必填 — 缺失会被服务端 invalid_argument
    (2026-10-01 实测)。客户端未提供时用默认 0.95 补位。
    """
    if temperature is None and top_p is None:
        return None
    cfg = field_varint(1, 1) + field_varint(2, max_ctx) + field_varint(3, 400)
    if temperature is not None:
        t = float(temperature)
        if t <= 0:            # 服务端拒绝 0.0 (实测 invalid_argument), 钳到 0.01
            t = 0.01
        cfg += field_f64(5, t)
    cfg += field_varint(7, int(top_k))
    cfg += field_f64(8, float(top_p) if top_p is not None else 0.95)
    return cfg


def frame(payload: bytes, flag: int = 0) -> bytes:
    return bytes([flag]) + struct.pack(">I", len(payload)) + payload


# ---------------------------------------------------------------- 推理调用

def get_chat_message(messages: list, on_delta=None, on_thinking=None,
                     timeout: int = 300, model: str = "swe-1-6-slow",
                     cancel: threading.Event = None, account=None, tools=None,
                     temperature=None, top_p=None):
    """执行一次推理。返回 (答案全文, 模型名, usage dict, tool_calls 列表)。

    - messages: dict 列表 (见 build_request)
    - tools: [{name, description, input_schema}] 映射到 field 10
    - temperature/top_p: 客户端采样参数 (field 8, 实测生效)
    - 响应 field 6 流 = 工具调用 {1:call_id, 2:name, 3:args_json 增量} → 聚合返回
    - account=Account 时维护其熔断与用量统计; cancel 置位立即断开
    """
    if account is not None:
        auth = account.api_key
        base = account.base_url
        pool = account.pool
        fp = account.fp or None
    else:
        auth, base = read_credentials()
        pool = _get_pool(base)
        fp = None
    path = "/exa.api_server_pb.ApiServerService/GetChatMessage"
    payload = build_request(messages, auth, model=model, fp=fp, tools=tools,
                            cfg=build_completion_config(temperature, top_p))
    headers = {"authorization": f"Basic {auth}",
               "content-type": "application/connect+proto",
               "connect-protocol-version": "1",
               "connect-accept-encoding": "identity",
               "user-agent": "connect-rpc/1.x devin-cli/3000.11.3"}
    body = frame(payload)

    if account is not None:
        account.inflight += 1
    last_exc = None
    try:
        for attempt in (0, 1):  # 最多一次重试 (仅限连接层失败)
            conn = pool.get()
            answer, model_seen, usage, trailer = [], None, {}, None
            tool_calls = {}
            broken = False
            try:
                conn.request("POST", path, body=body, headers=headers)
                resp = conn.getresponse()
                buf = b""
                while True:
                    if cancel is not None and cancel.is_set():
                        raise Cancelled()
                    chunk = resp.read(CHUNK)
                    if not chunk:
                        break
                    buf += chunk
                    while len(buf) >= 5:
                        ln = struct.unpack(">I", buf[1:5])[0]
                        if len(buf) < 5 + ln:
                            break
                        fl, pl = buf[0], buf[5:5 + ln]
                        buf = buf[5 + ln:]
                        if fl == 2:
                            trailer = pl.decode("utf-8", "replace")
                            continue
                        f = wire_fields(pl)
                        if 3 in f:
                            t = f[3][0].decode("utf-8", "replace")
                            answer.append(t)
                            if on_delta:
                                on_delta(t)
                        if 9 in f:
                            t = f[9][0].decode("utf-8", "replace")
                            if on_thinking:
                                on_thinking(t)
                        if 6 in f:
                            # 工具调用流: {1:call_id, 2:name, 3:args_json 增量}
                            sub = wire_fields(f[6][0])
                            cid_b = sub.get(1, [b""])[0]
                            cid = cid_b.decode("utf-8", "replace") if cid_b else ""
                            if cid:
                                tc = tool_calls.setdefault(
                                    cid, {"id": cid, "name": None, "args": ""})
                                n_b = sub.get(2, [None])[0]
                                if n_b and isinstance(n_b, (bytes, bytearray)):
                                    tc["name"] = n_b.decode("utf-8", "replace")
                                a_b = sub.get(3, [None])[0]
                                if a_b and isinstance(a_b, (bytes, bytearray)):
                                    tc["args"] += a_b.decode("utf-8", "replace")
                        if 7 in f:
                            meta = wire_fields(f[7][0])
                            m9 = meta.get(9)
                            if m9 and isinstance(m9[0], (bytes, bytearray)):
                                model_seen = m9[0].decode()
                            if isinstance(meta.get(2, [None])[0], int):
                                usage["prompt_tokens"] = max(
                                    usage.get("prompt_tokens", 0), meta[2][0])
                            if isinstance(meta.get(3, [None])[0], int):
                                usage["completion_tokens"] = max(
                                    usage.get("completion_tokens", 0), meta[3][0])
                pool.put(conn)
                if trailer and trailer.strip() not in ("", "{}"):
                    try:
                        err = json.loads(trailer).get("error", {})
                        raise DeepError(err.get("code", "unknown"),
                                        err.get("message", trailer)
                                        + f" [payload_head={payload[:48].hex()}]")
                    except json.JSONDecodeError:
                        raise DeepError("unknown", trailer)
                if account is not None:
                    account.on_ok(usage)
                tc_list = [tool_calls[k] for k in sorted(tool_calls)]
                for tc in tc_list:
                    try:
                        tc["input"] = json.loads(tc["args"]) if tc["args"].strip() else {}
                    except json.JSONDecodeError:
                        tc["input"] = {"_raw": tc["args"]}
                return "".join(answer), model_seen, usage, tc_list
            except Cancelled:
                # 中途取消: 连接状态未知, 直接弃用; 非账号过错, 不计熔断
                pool.put(conn, broken=True)
                raise
            except DeepError as e:
                # 服务端已完成应答并给出 trailer, 连接可复用
                pool.put(conn)
                if account is not None:
                    account.on_fail(e.code, e.message, model)
                raise
            except (http.client.HTTPException, OSError, ssl.SSLError) as e:
                broken = True
                last_exc = e
            finally:
                if broken:
                    pool.put(conn, broken=True)
        if account is not None:
            account.on_fail("transport", str(last_exc), model)
        raise ConnectionError(f"devin rpc failed after retry: {last_exc}")
    finally:
        if account is not None:
            account.inflight -= 1


def get_user_status(account=None, timeout=60):
    """拉取账号状态 (逆向: /1/13 = PlanStatus)。

    返回 {plan, team, daily_pct, weekly_pct, daily_reset, period_reset, raw_len}
    - f14=daily_quota_remaining_percent, f15=weekly, f17=daily_reset, f18=period_reset
    """
    if account is not None:
        auth, base, pool, fp = account.api_key, account.base_url, account.pool, (account.fp or None)
    else:
        auth, base = read_credentials()
        pool = _get_pool(base)
        fp = None
    ci = (field(1, b"chisel") + field(2, b"3000.11.3") + field(3, auth.encode())
          + field(4, b"en") + field(5, b"windows") + field(7, b"3000.11.3")
          + field(12, b"chisel"))
    if fp:
        ci += field(31, fp)
    body = field(1, ci)
    conn = pool.get()
    try:
        conn.request("POST",
            "/exa.seat_management_pb.SeatManagementService/GetUserStatus",
            body=body,
            headers={"authorization": f"Basic {auth}",
                     "content-type": "application/proto",
                     "connect-protocol-version": "1"})
        resp = conn.getresponse().read()
        pool.put(conn)
    except Exception:
        pool.put(conn, broken=True)
        raise
    f1 = wire_fields(resp).get(1)
    if not f1:
        return {"raw_len": len(resp)}
    top = wire_fields(f1[0])
    out = {"raw_len": len(resp)}
    plan_segs = top.get(13)
    if plan_segs:
        pf = wire_fields(plan_segs[0])
        out["daily_pct"] = pf.get(14, [None])[0]
        out["weekly_pct"] = pf.get(15, [None])[0]
        out["daily_reset"] = pf.get(17, [None])[0]
        out["period_reset"] = pf.get(18, [None])[0]
        name_segs = pf.get(1)
        if name_segs:
            blob = name_segs[0]
            if isinstance(blob, (bytes, bytearray)):
                txt = blob.decode("utf-8", "replace")
                for cand in ("Free", "Pro", "Team", "Enterprise", "Ultimate"):
                    if cand in txt:
                        out["plan"] = cand
                        break
                else:
                    out["plan"] = "unknown"
    return out
