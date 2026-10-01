#!/usr/bin/env python3
"""deep_pool.py — 多账号号池: 调度策略 + 熔断 + 每账号独立出口代理。

配置 (ACCOUNTS_FILE 环境变量, 默认脚本目录 accounts.json):
{
  "strategy": "least_inflight",     // round_robin | least_inflight | weighted | failover
  "max_attempts": 3,
  "accounts": [
    {"name": "a1",
     "api_key": "devin-session-token$eyJ...",        // 必填
     "api_server_url": "https://server.codeium.com", // 可省略用默认
     "fp_hex": "174648f8...",                         // 可省略 → 共享 ci31.bin
     "proxy": "http://user:pass@HOST:PORT | socks5://HOST:PORT",  // 可省略=直连
     "weight": 1}
  ]
}
无 accounts.json 时回退单账号模式 (DEVIN_API_KEY/credentials.toml)。
"""
import base64
import http.client
import json
import os
import queue
import random
import socket
import ssl
import struct
import threading
import time
import urllib.parse

DEFAULT_API_SERVER = "https://server.codeium.com"
_HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- 代理隧道

def _connect_via_http_proxy(proxy, target_host, timeout):
    """HTTP CONNECT 隧道, 返回已连通 target:443 的裸 socket。"""
    host = proxy.hostname
    port = proxy.port or 80
    sock = socket.create_connection((host, port), timeout=timeout)
    req = f"CONNECT {target_host}:443 HTTP/1.1\r\nHost: {target_host}:443\r\n"
    if proxy.username:
        cred = base64.b64encode(
            f"{proxy.username}:{proxy.password or ''}".encode()).decode()
        req += f"Proxy-Authorization: Basic {cred}\r\n"
    req += "\r\n"
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError("proxy closed during CONNECT")
        resp += chunk
    status = resp.split(b"\r\n", 1)[0]
    if b" 200" not in status:
        sock.close()
        raise OSError(f"proxy CONNECT failed: {status!r}")
    return sock


def _connect_via_socks5(proxy, target_host, timeout):
    """SOCKS5 (RFC1928, 支持 userpass) 隧道, 返回裸 socket。"""
    host = proxy.hostname
    port = proxy.port or 1080
    sock = socket.create_connection((host, port), timeout=timeout)
    need_auth = bool(proxy.username)
    sock.sendall(b"\x05\x01\x02" if need_auth else b"\x05\x01\x00")
    r = sock.recv(2)
    if len(r) < 2 or r[0] != 5:
        sock.close()
        raise OSError("bad socks5 greeting")
    if r[1] == 2 and need_auth:
        u = (proxy.username or "").encode()
        p = (proxy.password or "").encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        r = sock.recv(2)
        if len(r) < 2 or r[1] != 0:
            sock.close()
            raise OSError("socks5 auth failed")
    elif r[1] != 0:
        sock.close()
        raise OSError(f"socks5 no acceptable method: {r[1]}")
    addr = target_host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr
                 + struct.pack(">H", 443))
    r = sock.recv(4)
    if len(r) < 4 or r[1] != 0:
        sock.close()
        raise OSError(f"socks5 connect failed: {r[1] if len(r) > 1 else '?'}")
    atype = r[3]
    if atype == 1:
        sock.recv(4 + 2)
    elif atype == 3:
        ln = sock.recv(1)[0]
        sock.recv(ln + 2)
    elif atype == 4:
        sock.recv(16 + 2)
    return sock


class ProxiedHTTPSConnection(http.client.HTTPSConnection):
    """https 连接, 可选经 http/socks5 代理隧道; 供连接池复用。"""

    def __init__(self, host, proxy_url=None, ctx=None, timeout=300):
        super().__init__(host, 443, context=ctx, timeout=timeout)
        self._proxy = urllib.parse.urlparse(proxy_url) if proxy_url else None
        self._proxy_url = proxy_url

    def connect(self):
        if self._proxy is None:
            super().connect()
            return
        scheme = (self._proxy.scheme or "http").lower()
        if scheme in ("http", "https"):
            raw = _connect_via_http_proxy(self._proxy, self.host, self.timeout)
        elif scheme in ("socks5", "socks5h"):
            raw = _connect_via_socks5(self._proxy, self.host, self.timeout)
        else:
            raise OSError(f"unsupported proxy scheme: {scheme}")
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class ConnPool:
    """每 (账号, 代理) 一个的 HTTPS keep-alive 池。"""

    def __init__(self, host, proxy_url=None, maxsize=16):
        self.host = host
        self.proxy_url = proxy_url
        self.maxsize = maxsize
        self._pool = queue.LifoQueue(maxsize=maxsize)
        self._ctx = ssl.create_default_context()

    def _new(self):
        return ProxiedHTTPSConnection(self.host, self.proxy_url, ctx=self._ctx)

    def get(self):
        try:
            return self._pool.get_nowait()
        except queue.Empty:
            return self._new()

    def put(self, conn, broken=False):
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


# ---------------------------------------------------------------- Account

class Account:
    def __init__(self, cfg: dict, default_fp: bytes):
        self.name = cfg.get("name") or f"acc-{id(cfg)}"
        self.api_key = cfg["api_key"]                 # 含 devin-session-token$ 前缀
        self.base_url = (cfg.get("api_server_url")
                         or DEFAULT_API_SERVER).rstrip("/")
        fp_hex = cfg.get("fp_hex")
        self.fp = bytes.fromhex(fp_hex) if fp_hex else default_fp
        self.proxy = cfg.get("proxy") or None
        self.weight = float(cfg.get("weight", 1))
        self.enabled = True
        # 运行时状态
        self.inflight = 0
        self.total = 0
        self.ok = 0
        self.fail = 0
        self.prompt_tok = 0
        self.completion_tok = 0
        self.fail_streak = 0
        self.cooldown_until = 0.0
        self.last_err = None
        self.denied_models = set()
        # 配额 (GetUserStatus /1/13 PlanStatus, 逆向确认)
        self.plan = None
        self.daily_pct = None
        self.weekly_pct = None
        self.daily_reset = None
        self.period_reset = None
        self.quota_ts = 0.0
        self._pool = None
        self._lock = threading.Lock()

    @property
    def pool(self) -> ConnPool:
        with self._lock:
            if self._pool is None:
                host = urllib.parse.urlparse(self.base_url).hostname
                self._pool = ConnPool(host, self.proxy)
        return self._pool

    def available(self, model: str = None) -> bool:
        if not self.enabled:
            return False
        if time.time() < self.cooldown_until:
            return False
        if model and model in self.denied_models:
            return False
        return True

    def on_ok(self, usage: dict):
        self.total += 1
        self.ok += 1
        self.fail_streak = 0
        self.cooldown_until = 0.0
        self.last_err = None
        self.prompt_tok += usage.get("prompt_tokens", 0)
        self.completion_tok += usage.get("completion_tokens", 0)

    def on_fail(self, code: str, message: str, model: str = None):
        """按错误类型熔断。返回 cooldown 秒数。"""
        self.total += 1
        self.fail += 1
        self.fail_streak += 1
        self.last_err = f"{code}: {message[:120]}"
        now = time.time()
        if code == "unauthenticated":
            self.cooldown_until = now + 1800          # token 失效, 长冷却
            return 1800
        if code == "permission_denied" and model:
            self.denied_models.add(model)             # (账号,模型) 确定性拒绝
            return 0
        if code == "failed_precondition":
            self.cooldown_until = now + 60
            return 60
        # 传输/5xx/unknown → 指数退避 5s*2^n, 封顶 5min
        cd = min(5 * (2 ** (self.fail_streak - 1)), 300)
        self.cooldown_until = now + cd
        return cd

    def refresh_quota(self):
        from deep_client import get_user_status
        try:
            q = get_user_status(account=self)
            self.plan = q.get("plan")
            self.daily_pct = q.get("daily_pct")
            self.weekly_pct = q.get("weekly_pct")
            self.daily_reset = q.get("daily_reset")
            self.period_reset = q.get("period_reset")
            self.quota_ts = time.time()
        except Exception as e:  # noqa: BLE001
            self.last_err = f"quota: {e}"

    def snapshot(self) -> dict:
        proxy_host = None
        if self.proxy:
            p = urllib.parse.urlparse(self.proxy)
            proxy_host = f"{p.scheme}://{p.hostname}:{p.port}"
        return {
            "name": self.name, "enabled": self.enabled,
            "available": self.available(),
            "proxy": proxy_host, "weight": self.weight,
            "inflight": self.inflight, "total": self.total,
            "ok": self.ok, "fail": self.fail,
            "prompt_tokens": self.prompt_tok,
            "completion_tokens": self.completion_tok,
            "fail_streak": self.fail_streak,
            "cooldown_left_s": max(0, round(self.cooldown_until - time.time())),
            "denied_models": sorted(self.denied_models),
            "last_err": self.last_err,
            "plan": self.plan, "daily_pct": self.daily_pct,
            "weekly_pct": self.weekly_pct,
            "daily_reset": self.daily_reset, "period_reset": self.period_reset,
        }


# ---------------------------------------------------------------- 调度器

class AccountPool:
    def __init__(self, accounts: list, strategy: str = "least_inflight",
                 max_attempts: int = 3):
        self.accounts = accounts
        self.strategy = strategy
        self.max_attempts = max(1, min(max_attempts, max(1, len(accounts))))
        self._rr = 0
        self._lock = threading.Lock()

    # -- 选择 --
    def _candidates(self, model: str) -> list:
        return [a for a in self.accounts if a.available(model)]

    def acquire(self, model: str = None, exclude: tuple = ()) -> "Account":
        cands = [a for a in self._candidates(model) if a not in exclude]
        if not cands:
            raise RuntimeError(
                f"no available account (model={model}, strategy={self.strategy})")
        if self.strategy == "round_robin":
            with self._lock:
                self._rr += 1
            return cands[self._rr % len(cands)]
        if self.strategy == "weighted":
            weights = [max(a.weight, 0.001) for a in cands]
            return random.choices(cands, weights=weights, k=1)[0]
        if self.strategy == "failover":
            return cands[0]
        # 默认 least_inflight
        return min(cands, key=lambda a: (a.inflight, a.total))

    # -- 生命周期 --
    @classmethod
    def load(cls) -> "AccountPool":
        """accounts.json > (单账号回退: DEVIN_API_KEY / credentials.toml)。"""
        from deep_client import read_credentials, client_fingerprint
        path = os.environ.get("ACCOUNTS_FILE",
                              os.path.join(_HERE, "accounts.json"))
        default_fp = client_fingerprint()
        if os.path.exists(path):
            cfg = json.load(open(path, encoding="utf-8"))
            accounts = [Account(a, default_fp) for a in cfg.get("accounts", [])
                        if a.get("api_key")]
            return cls(accounts, cfg.get("strategy", "least_inflight"),
                       cfg.get("max_attempts", 3))
        # 单账号回退
        key, url = read_credentials()
        acc = Account({"name": "default", "api_key": key,
                       "api_server_url": url}, default_fp)
        return cls([acc], "failover", 1)

    def start_quota_refresher(self, interval: float = 300):
        """后台定时刷新各账号配额 (daemon)。"""
        def loop():
            while True:
                for a in self.accounts:
                    if a.enabled:
                        a.refresh_quota()
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True).start()

    def reload(self):
        new = AccountPool.load()
        self.accounts = new.accounts
        self.strategy = new.strategy
        self.max_attempts = new.max_attempts

    def refresh_quota(self):
        from deep_client import get_user_status
        try:
            q = get_user_status(account=self)
            self.plan = q.get("plan")
            self.daily_pct = q.get("daily_pct")
            self.weekly_pct = q.get("weekly_pct")
            self.daily_reset = q.get("daily_reset")
            self.period_reset = q.get("period_reset")
            self.quota_ts = time.time()
        except Exception as e:  # noqa: BLE001
            self.last_err = f"quota: {e}"

    def snapshot(self) -> dict:
        return {"strategy": self.strategy, "max_attempts": self.max_attempts,
                "accounts": [a.snapshot() for a in self.accounts]}
