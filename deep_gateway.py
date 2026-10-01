#!/usr/bin/env python3
"""deep_gateway.py — v4: 多账号号池 + OpenAI/Anthropic 全兼容 + 工具调用 + 思维链。

v4 新增 (基于 Devin 协议深度逆向):
  - tools[] 映射: Anthropic/OpenAI 工具 → field10; 响应 field6 流 → tool_use/tool_calls
  - 工具消息: assistant.tool_use → role2{6:call}; tool_result → role4{"Tool 'x' …"}
  - reasoning_content (OpenAI) / thinking blocks (Anthropic) 思维链透传
  - SSE 心跳 (: keepalive 注释帧) 防中间层空闲超时
  - GET /pool/egress 逐账号实测出口 IP
"""
import asyncio
import http.client
import json
import os
import ssl
import threading
import time
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from deep_client import DeepError, Cancelled, get_chat_message
from deep_pool import AccountPool

app = FastAPI(title="devin-deep-gateway")

POOL = AccountPool.load()

@app.on_event("startup")
async def _startup():
    POOL.start_quota_refresher(300)
    for a in POOL.accounts:
        if a.enabled:
            await asyncio.get_running_loop().run_in_executor(None, a.refresh_quota)

# ---------------------------------------------------------------- 运行统计
import collections
STATS = {"start": time.time(), "total": 0, "ok": 0, "fail": 0,
         "prompt_tokens": 0, "completion_tokens": 0}
RECENT = collections.deque(maxlen=50)


def _record(source, account, model, ok, usage, dur_ms, err=None):
    STATS["total"] += 1
    STATS["ok" if ok else "fail"] += 1
    u = usage or {}
    STATS["prompt_tokens"] += u.get("prompt_tokens", 0)
    STATS["completion_tokens"] += u.get("completion_tokens", 0)
    RECENT.appendleft({
        "ts": time.strftime("%H:%M:%S"), "source": source,
        "account": account, "model": model, "ok": ok,
        "pt": u.get("prompt_tokens", 0), "ct": u.get("completion_tokens", 0),
        "ms": round(dur_ms),
        "err": ("" if err is None else str(err))[:90]})

GATEWAY_API_KEY = os.environ.get("GATEWAY_API_KEY", "")
MODELS = [m.strip() for m in os.environ.get(
    "GATEWAY_MODELS", "swe-1-6-slow").split(",") if m.strip()]
DEFAULT_MODEL = os.environ.get("GATEWAY_DEFAULT_MODEL", "swe-1-6-slow")
HEARTBEAT_S = float(os.environ.get("GATEWAY_HEARTBEAT_S", "15"))
REASONING = os.environ.get("GATEWAY_REASONING", "1") == "1"


def pick(model):
    return model if model else DEFAULT_MODEL


def check_auth(request: Request):
    if not GATEWAY_API_KEY:
        return
    supplied = (request.headers.get("authorization", "").removeprefix("Bearer ").strip()
                or request.headers.get("x-api-key", ""))
    if supplied != GATEWAY_API_KEY:
        raise HTTPException(401, "invalid gateway key")


# ---------------------------------------------------------------- 消息转换

ROLE_USER = 1
ROLE_ASSISTANT = 2   # 承载工具调用 (content 可空)
ROLE_TOOL = 4        # 工具结果, 文本形如 "Tool 'name' output: …"


def _blocks(content) -> list:
    """content 统一为 block 列表 [{type, text?/…}]。"""
    if isinstance(content, str):
        return [{"type": "text", "text": content}] if content else []
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    return []


def convert_anthropic(messages: list, system) -> tuple[list, list]:
    """Anthropic messages → (devin_messages, pending_tool_defs 不处理)。

    策略: 只使用已验证的消息形态 (role1 文本 / role2 工具调用 / role4 工具结果);
    assistant 纯文本折叠进下一条 user 消息头 (role2 纯文本形态未验证)。
    """
    out = []
    tool_use_names = {}   # tool_use id → name
    carry = []            # 待折叠的 assistant 文本

    def flush_carry_into_user(text):
        if carry:
            text = ("[Previous assistant reply]\n"
                    + "\n".join(carry) + "\n\n" + text) if text else "\n".join(carry)
            carry.clear()
        return text

    if system:
        s = system if isinstance(system, str) else "\n".join(
            b.get("text", "") for b in system if isinstance(b, dict))
        out.append({"uuid": str(uuid.uuid4()), "role": ROLE_USER,
                    "content": f"[System instructions]\n{s}"})

    for m in messages:
        role = m.get("role")
        blocks = _blocks(m.get("content"))
        if role == "user":
            results = [b for b in blocks if b.get("type") == "tool_result"]
            texts = [b.get("text", "") for b in blocks if b.get("type") == "text"]
            for tr in results:
                name = tool_use_names.get(tr.get("tool_use_id"), "tool")
                inner = tr.get("content", "")
                if isinstance(inner, list):
                    inner = "\n".join(b.get("text", "") for b in inner
                                      if isinstance(b, dict))
                out.append({"uuid": str(uuid.uuid4()), "role": ROLE_TOOL,
                            "content": f"Tool '{name}' output: {inner}",
                            "term": 7})
            if texts:
                text = "\n".join(t for t in texts if t)
                text = flush_carry_into_user(text)
                out.append({"uuid": str(uuid.uuid4()), "role": ROLE_USER,
                            "content": text})
        elif role == "assistant":
            uses = [b for b in blocks if b.get("type") == "tool_use"]
            texts = [b.get("text", "") for b in blocks if b.get("type") == "text"]
            if texts:   # role2 文本形态已实测支持 (2026-10-01)
                out.append({"uuid": str(uuid.uuid4()), "role": ROLE_ASSISTANT,
                            "content": "\n".join(t for t in texts if t)})
            for b in uses:
                tool_use_names[b["id"]] = b.get("name", "tool")
                out.append({"uuid": str(uuid.uuid4()), "role": ROLE_ASSISTANT,
                            "content": "",
                            "tool_call": {"id": b["id"],
                                          "name": b.get("name", "tool"),
                                          "args_json": json.dumps(
                                              b.get("input", {}),
                                              ensure_ascii=False)},
                            "term": 11})
    # 尾部 carry 无 user 接收时落为独立 user 消息
    if carry:
        out.append({"uuid": str(uuid.uuid4()), "role": ROLE_USER,
                    "content": "\n".join(carry)})
        carry.clear()
    return out, tool_use_names


def convert_openai(messages: list) -> list:
    """OpenAI messages → devin messages (含 tool_calls / role:tool)。"""
    out = []
    tool_names = {}
    carry = []
    for m in messages:
        role = m.get("role")
        content = m.get("content")
        if role == "system":
            if content:
                out.append({"uuid": str(uuid.uuid4()), "role": ROLE_USER,
                            "content": f"[System instructions]\n{content}"})
        elif role == "user":
            text = content if isinstance(content, str) else "\n".join(
                b.get("text", "") for b in (content or []) if isinstance(b, dict))
            if carry:
                text = ("[Previous assistant reply]\n" + "\n".join(carry)
                        + "\n\n" + (text or ""))
                carry.clear()
            if text:
                out.append({"uuid": str(uuid.uuid4()), "role": ROLE_USER,
                            "content": text})
        elif role == "assistant":
            if content:
                out.append({"uuid": str(uuid.uuid4()), "role": ROLE_ASSISTANT,
                            "content": content})
            for tc in m.get("tool_calls", []) or []:
                fn = tc.get("function", {})
                name = fn.get("name", "tool")
                tool_names[tc.get("id", "")] = name
                out.append({"uuid": str(uuid.uuid4()), "role": ROLE_ASSISTANT,
                            "content": "",
                            "tool_call": {"id": tc.get("id", f"call_{uuid.uuid4().hex[:8]}"),
                                          "name": name,
                                          "args_json": fn.get("arguments") or "{}"},
                            "term": 11})
        elif role == "tool":
            name = tool_names.get(m.get("tool_call_id"), m.get("name", "tool"))
            out.append({"uuid": str(uuid.uuid4()), "role": ROLE_TOOL,
                        "content": f"Tool '{name}' output: {content}",
                        "term": 7})
    if carry:
        out.append({"uuid": str(uuid.uuid4()), "role": ROLE_USER,
                    "content": "\n".join(carry)})
    return out


def convert_responses(input_body, instructions) -> list:
    """OpenAI Responses API input → devin messages。

    input: str 或 item 列表:
      {role:user/assistant, content:str|[{type:input_text/output_text,...}]}
      {type:function_call, call_id, name, arguments}
      {type:function_call_output, call_id, output}
      {type:reasoning, ...} → 忽略
    instructions → 顶部 [System instructions]
    """
    items = ([{"role": "user", "content": input_body}]
             if isinstance(input_body, str) else list(input_body or []))
    out = []
    call_names = {}
    carry = []

    def push_user(text):
        if carry:
            text = ("[Previous assistant reply]\n" + "\n".join(carry)
                    + "\n\n" + (text or ""))
            carry.clear()
        if text:
            out.append({"uuid": str(uuid.uuid4()), "role": ROLE_USER,
                        "content": text})

    if instructions:
        s = instructions if isinstance(instructions, str) else "\n".join(
            b.get("text", "") for b in instructions if isinstance(b, dict))
        out.append({"uuid": str(uuid.uuid4()), "role": ROLE_USER,
                    "content": f"[System instructions]\n{s}"})

    for it in items:
        t = it.get("type")
        if t == "function_call":
            call_names[it.get("call_id", "")] = it.get("name", "tool")
            out.append({"uuid": str(uuid.uuid4()), "role": ROLE_ASSISTANT,
                        "content": "",
                        "tool_call": {"id": it.get("call_id",
                                                      f"call_{uuid.uuid4().hex[:8]}"),
                                      "name": it.get("name", "tool"),
                                      "args_json": it.get("arguments") or "{}"},
                        "term": 11})
        elif t == "function_call_output":
            nm = call_names.get(it.get("call_id", ""), "tool")
            out.append({"uuid": str(uuid.uuid4()), "role": ROLE_TOOL,
                        "content": f"Tool '{nm}' output: {it.get('output', '')}",
                        "term": 7})
        elif t == "reasoning":
            continue
        else:
            role = it.get("role", "user")
            c = it.get("content")
            text = c if isinstance(c, str) else "".join(
                b.get("text", "") for b in (c or []) if isinstance(b, dict)
                and b.get("type") in ("input_text", "output_text", "text",
                                      "refusal"))
            if role == "user":
                push_user(text)
            else:
                if text:
                    out.append({"uuid": str(uuid.uuid4()), "role": ROLE_ASSISTANT,
                                "content": text})
    push_user("")
    return out


# ---------------------------------------------------------------- 调度推理

def infer_with_pool(messages: list, model: str, tools=None, on_delta=None,
                    on_thinking=None, cancel: threading.Event = None,
                    source: str = "?", temperature=None, top_p=None):
    """号池调度推理。返回 (答案, 模型, usage, 账号名, tool_calls)。"""
    excluded = []
    last_err = None
    emitted = {"v": False}
    t0 = time.time()

    def _delta(t):
        emitted["v"] = True
        if on_delta:
            on_delta(t)

    for _ in range(max(1, POOL.max_attempts)):
        try:
            acc = POOL.acquire(model, exclude=tuple(excluded))
        except RuntimeError:
            break
        try:
            full, model_seen, usage, tc = get_chat_message(
                messages, model=model, account=acc, tools=tools,
                cancel=cancel, on_delta=_delta, on_thinking=on_thinking,
                temperature=temperature, top_p=top_p)
            _record(source, acc.name, model, True, usage,
                    (time.time() - t0) * 1000)
            return full, model_seen, usage, acc.name, tc
        except Cancelled:
            raise
        except DeepError as e:
            last_err = e
            excluded.append(acc)
            if emitted["v"]:
                _record(source, acc.name, model, False, None,
                        (time.time() - t0) * 1000, f"{e.code}: {e.message}")
                raise
            continue
        except (ConnectionError, OSError, http.client.HTTPException) as e:
            last_err = e
            excluded.append(acc)
            if emitted["v"]:
                _record(source, acc.name, model, False, None,
                        (time.time() - t0) * 1000, str(e))
                raise
            continue
    _record(source, "-", model, False, None, (time.time() - t0) * 1000,
            str(last_err) if last_err else "pool exhausted")
    raise last_err or RuntimeError("account pool exhausted")


class StreamJob:
    def __init__(self, messages: list, model: str, tools=None, source="?",
                 temperature=None, top_p=None):
        self.stop = threading.Event()
        self._aq: asyncio.Queue = asyncio.Queue()
        self._loop = asyncio.get_running_loop()
        self.t = threading.Thread(target=self._run,
                                  args=(messages, model, tools, source,
                                        temperature, top_p), daemon=True)
        self.t.start()

    def _push(self, item):
        self._loop.call_soon_threadsafe(self._aq.put_nowait, item)

    def _run(self, messages, model, tools, source="?", temperature=None,
             top_p=None):
        def delta(t):
            self._push(("delta", t))

        def thinking(t):
            if REASONING:
                self._push(("thinking", t))

        def toolcall(tc):
            self._push(("tool_use", tc))

        try:
            full, model_seen, usage, acc_name, tc_list = infer_with_pool(
                messages, model, tools=tools, cancel=self.stop,
                on_delta=delta, on_thinking=thinking)
            self._push(("done", {"model": model_seen, "usage": usage,
                                 "full": full, "account": acc_name,
                                 "tool_calls": tc_list}))
        except Cancelled:
            self._push(("cancelled", None))
        except DeepError as e:
            self._push(("error", f"{e.code}: {e.message}"))
        except Exception as e:  # noqa: BLE001
            self._push(("error", f"{type(e).__name__}: {e}"))

    async def chunks(self):
        while True:
            kind, val = await self._aq.get()
            yield kind, val
            if kind in ("done", "error", "cancelled"):
                return

    def cancel(self):
        self.stop.set()


async def with_heartbeat(gen, interval: float = HEARTBEAT_S):
    """空闲期发 SSE 注释帧保活。"""
    q: asyncio.Queue = asyncio.Queue()
    SENTINEL = object()

    async def pump():
        try:
            async for item in gen:
                await q.put(item)
        finally:
            await q.put(SENTINEL)

    task = asyncio.create_task(pump())
    try:
        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=interval)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue
            if item is SENTINEL:
                return
            yield item
    finally:
        task.cancel()


def usage_of(stats) -> dict:
    u = stats if isinstance(stats, dict) else {}
    p = u.get("prompt_tokens", 0)
    c = u.get("completion_tokens", 0)
    return {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c}


# ---------------------------------------------------------------- 端点

@app.get("/v1/models")
async def list_models():
    return {"object": "list",
            "data": [{"id": m, "object": "model", "owned_by": "devin"}
                     for m in MODELS]}


@app.get("/healthz")
async def healthz():
    return {"ok": True, "mode": "deep-v4-tools", "models": MODELS,
            "default": DEFAULT_MODEL,
            "pool": {"strategy": POOL.strategy,
                     "accounts": len(POOL.accounts),
                     "available": sum(1 for a in POOL.accounts if a.available())}}


@app.get("/pool/egress")
async def pool_egress():
    """逐账号实测出口 IP (走各自的代理配置访问 ipinfo.io)。"""
    import urllib.parse

    async def one(acc):
        def work():
            from deep_pool import ProxiedHTTPSConnection
            ctx = ssl.create_default_context()
            conn = ProxiedHTTPSConnection("ipinfo.io", acc.proxy, ctx=ctx,
                                          timeout=20)
            try:
                conn.request("GET", "/ip", headers={"user-agent": "curl/8"})
                r = conn.getresponse()
                return r.read().decode().strip()[:64]
            finally:
                conn.close()
        try:
            return await asyncio.to_thread(work)
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {e}"

    results = {}
    for a in POOL.accounts:
        if a.enabled:
            results[a.name] = await one(a)
    return {"egress": results}


@app.post("/pool/status")
async def pool_status_post():
    return POOL.snapshot()


@app.get("/pool/status")
async def pool_status():
    return POOL.snapshot()


@app.post("/pool/reload")
async def pool_reload():
    POOL.reload()
    return {"reloaded": True, "accounts": len(POOL.accounts)}


@app.post("/pool/{name}/disable")
async def pool_disable(name: str):
    for a in POOL.accounts:
        if a.name == name:
            a.enabled = False
            return {"name": name, "enabled": False}
    raise HTTPException(404, f"account {name} not found")


@app.post("/pool/{name}/enable")
async def pool_enable(name: str):
    for a in POOL.accounts:
        if a.name == name:
            a.enabled = True
            a.cooldown_until = 0.0
            a.fail_streak = 0
            return {"name": name, "enabled": True}
    raise HTTPException(404, f"account {name} not found")


# ---------------------------------------------------------------- OpenAI

@app.post("/v1/chat/completions")
async def openai_chat(request: Request):
    check_auth(request)
    body = await request.json()
    stream = bool(body.get("stream"))
    model = pick(body.get("model"))
    messages = convert_openai(body.get("messages", []))
    temp, tp = body.get("temperature"), body.get("top_p")
    tools = None
    if body.get("tools"):
        tools = [{"name": t["function"]["name"],
                  "description": t["function"].get("description", ""),
                  "input_schema": t["function"].get("parameters", {})}
                 for t in body["tools"] if "function" in t]
    cid = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    ts = int(time.time())

    if not stream:
        try:
            full, model_seen, usage, acc_name, tc = await asyncio.to_thread(
                infer_with_pool, messages, model, tools, None, None, None, "chat",
                temp, tp)
        except DeepError as e:
            raise HTTPException(502, f"devin error: {e.code}: {e.message}") from e
        except (ConnectionError, RuntimeError) as e:
            raise HTTPException(503, f"pool unavailable: {e}") from e
        msg = {"role": "assistant", "content": full or None}
        if tc:
            msg["tool_calls"] = [
                {"id": t["id"], "type": "function",
                 "function": {"name": t["name"],
                              "arguments": json.dumps(t["input"],
                                                      ensure_ascii=False)}}
                for t in tc]
        return JSONResponse(
            {"id": cid, "object": "chat.completion", "created": ts,
             "model": model_seen or model,
             "choices": [{"index": 0, "message": msg,
                          "finish_reason": "tool_calls" if tc else "stop"}],
             "usage": usage_of(usage)},
            headers={"x-devin-account": acc_name})

    async def sse():
        job = StreamJob(messages, model, tools, source="chat",
                        temperature=temp, top_p=tp)
        first = True
        try:
            async for kind, val in job.chunks():
                if kind == "delta":
                    if first:
                        first = False
                        yield f'data: {json.dumps({"id":cid,"object":"chat.completion.chunk","created":ts,"model":model,"choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":None}]})}\n\n'
                    yield f'data: {json.dumps({"id":cid,"object":"chat.completion.chunk","created":ts,"model":model,"choices":[{"index":0,"delta":{"content":val},"finish_reason":None}]})}\n\n'
                elif kind == "thinking":
                    yield f'data: {json.dumps({"id":cid,"object":"chat.completion.chunk","created":ts,"model":model,"choices":[{"index":0,"delta":{"reasoning_content":val},"finish_reason":None}]})}\n\n'
                elif kind == "tool_use":
                    pass  # 聚合到 done 统一发
                elif kind == "done":
                    finish = "stop"
                    if val.get("tool_calls"):
                        finish = "tool_calls"
                        for t in val["tool_calls"]:
                            yield f'data: {json.dumps({"id":cid,"object":"chat.completion.chunk","created":ts,"model":model,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":t["id"],"type":"function","function":{"name":t["name"],"arguments":json.dumps(t["input"],ensure_ascii=False)}}]},"finish_reason":None}]})}\n\n'
                    yield f'data: {json.dumps({"id":cid,"object":"chat.completion.chunk","created":ts,"model":val.get("model") or model,"choices":[{"index":0,"delta":{},"finish_reason":finish}]})}\n\n'
                    yield "data: [DONE]\n\n"
                else:
                    yield f'data: {json.dumps({"id":cid,"object":"chat.completion.chunk","created":ts,"model":model,"choices":[{"index":0,"delta":{"content":f"[devin error: {val}]"},"finish_reason":"stop"}]})}\n\n'
                    yield "data: [DONE]\n\n"
        finally:
            job.cancel()

    return StreamingResponse(with_heartbeat(sse()),
                             media_type="text/event-stream")


# ---------------------------------------------------------------- Anthropic

@app.post("/v1/messages/count_tokens")
async def count_tokens(request: Request):
    check_auth(request)
    body = await request.json()
    n = 0
    for m in body.get("messages", []):
        c = m.get("content", "")
        if isinstance(c, list):
            c = " ".join(str(b.get("text", "")) + str(b.get("input", ""))
                         for b in c if isinstance(b, dict))
        n += len(str(c))
    n += len(str(body.get("system", "")))
    return {"input_tokens": max(1, n // 4)}


@app.post("/v1/messages")
async def anthropic_messages(request: Request):
    check_auth(request)
    body = await request.json()
    stream = bool(body.get("stream"))
    model = pick(body.get("model"))
    temp, tp = body.get("temperature"), body.get("top_p")
    messages, _ = convert_anthropic(body.get("messages", []),
                                    body.get("system"))
    temp, tp = body.get("temperature"), body.get("top_p")
    tools = None
    if body.get("tools"):
        tools = [{"name": t.get("name", "tool"),
                  "description": t.get("description", ""),
                  "input_schema": t.get("input_schema", {})}
                 for t in body["tools"]]
    mid = f"msg_{uuid.uuid4().hex[:24]}"

    def emit_start():
        return (f'event: message_start\ndata: {json.dumps({"type":"message_start","message":{"id":mid,"type":"message","role":"assistant","model":model,"content":[],"stop_reason":None,"usage":{"input_tokens":0,"output_tokens":0}}})}\n\n')

    if not stream:
        try:
            full, model_seen, usage, acc_name, tc = await asyncio.to_thread(
                infer_with_pool, messages, model, tools, None, None, None, "messages",
                temp, tp)
        except DeepError as e:
            raise HTTPException(502, f"devin error: {e.code}: {e.message}") from e
        except (ConnectionError, RuntimeError) as e:
            raise HTTPException(503, f"pool unavailable: {e}") from e
        u = usage_of(usage)
        content = []
        if full:
            content.append({"type": "text", "text": full})
        for t in tc:
            content.append({"type": "tool_use", "id": t["id"],
                            "name": t["name"], "input": t["input"]})
        return JSONResponse(
            {"id": mid, "type": "message", "role": "assistant",
             "model": model_seen or model, "content": content,
             "stop_reason": "tool_use" if tc else "end_turn",
             "stop_sequence": None,
             "usage": {"input_tokens": u["prompt_tokens"],
                       "output_tokens": u["completion_tokens"]}},
            headers={"x-devin-account": acc_name})

    blk = {"idx": 0, "open": False, "type": None}

    def block_open(btype):
        head = ""
        if not blk["open"]:
            blk["open"] = True
            blk["type"] = btype
            if btype == "text":
                head += f'event: content_block_start\ndata: {json.dumps({"type":"content_block_start","index":blk["idx"],"content_block":{"type":"text","text":""}})}\n\n'
            elif btype == "thinking":
                head += f'event: content_block_start\ndata: {json.dumps({"type":"content_block_start","index":blk["idx"],"content_block":{"type":"thinking","thinking":""}})}\n\n'
            elif btype == "tool_use":
                pass  # start 参数化, 在调用处发
        return head

    async def sse():
        job = StreamJob(messages, model, tools, source="messages",
                        temperature=temp, top_p=tp)
        started = False
        try:
            async for kind, val in job.chunks():
                if kind == "thinking":
                    if not started:
                        started = True
                        yield emit_start()
                    yield block_open("thinking")
                    yield f'event: content_block_delta\ndata: {json.dumps({"type":"content_block_delta","index":blk["idx"],"delta":{"type":"thinking_delta","thinking":val}})}\n\n'
                elif kind == "delta":
                    if blk["type"] == "thinking":
                        yield f'event: content_block_stop\ndata: {json.dumps({"type":"content_block_stop","index":blk["idx"]})}\n\n'
                        blk["idx"] += 1
                        blk["open"] = False
                    if not started:
                        started = True
                        yield emit_start()
                    yield block_open("text")
                    yield f'event: content_block_delta\ndata: {json.dumps({"type":"content_block_delta","index":blk["idx"],"delta":{"type":"text_delta","text":val}})}\n\n'
                elif kind == "done":
                    if not started:
                        started = True
                        yield emit_start()
                    if blk["open"]:
                        yield f'event: content_block_stop\ndata: {json.dumps({"type":"content_block_stop","index":blk["idx"]})}\n\n'
                        blk["open"] = False
                    stop = "end_turn"
                    for t in val.get("tool_calls", []):
                        yield f'event: content_block_start\ndata: {json.dumps({"type":"content_block_start","index":blk["idx"],"content_block":{"type":"tool_use","id":t["id"],"name":t["name"],"input":{}}})}\n\n'
                        yield f'event: content_block_delta\ndata: {json.dumps({"type":"content_block_delta","index":blk["idx"],"delta":{"type":"input_json_delta","partial_json":json.dumps(t["input"],ensure_ascii=False)}})}\n\n'
                        yield f'event: content_block_stop\ndata: {json.dumps({"type":"content_block_stop","index":blk["idx"]})}\n\n'
                        blk["idx"] += 1
                        stop = "tool_use"
                    yield f'event: message_delta\ndata: {json.dumps({"type":"message_delta","delta":{"stop_reason":stop,"stop_sequence":None},"usage":{"output_tokens":val.get("usage",{}).get("completion_tokens",0)}})}\n\n'
                    yield f'event: message_stop\ndata: {json.dumps({"type":"message_stop"})}\n\n'
                else:
                    if not started:
                        started = True
                        yield emit_start()
                    if blk["open"]:
                        yield f'event: content_block_stop\ndata: {json.dumps({"type":"content_block_stop","index":blk["idx"]})}\n\n'
                        blk["open"] = False
                    yield f'event: content_block_delta\ndata: {json.dumps({"type":"content_block_delta","index":blk["idx"],"delta":{"type":"text_delta","text":f"[devin error: {val}]"}})}\n\n'
                    yield f'event: content_block_stop\ndata: {json.dumps({"type":"content_block_stop","index":blk["idx"]})}\n\n'
                    yield f'event: message_delta\ndata: {json.dumps({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":None},"usage":{"output_tokens":0}})}\n\n'
                    yield f'event: message_stop\ndata: {json.dumps({"type":"message_stop"})}\n\n'
        finally:
            job.cancel()

    return StreamingResponse(with_heartbeat(sse()),
                             media_type="text/event-stream")


# ---------------------------------------------------------------- Responses API

@app.post("/v1/responses")
async def openai_responses(request: Request):
    """OpenAI Responses API (Codex CLI / 新版 SDK 的默认协议)。"""
    check_auth(request)
    body = await request.json()
    stream = bool(body.get("stream"))
    model = pick(body.get("model"))
    messages = convert_responses(body.get("input"), body.get("instructions"))
    temp, tp = body.get("temperature"), body.get("top_p")
    tools = None
    if body.get("tools"):
        tools = [{"name": t.get("name", "tool"),
                  "description": t.get("description", ""),
                  "input_schema": t.get("parameters", {})}
                 for t in body["tools"] if t.get("type") == "function"]
    rid = f"resp_{uuid.uuid4().hex[:24]}"
    ts = int(time.time())

    def base_response(status="in_progress", output=None, usage=None):
        u = usage or {}
        return {"id": rid, "object": "response", "created_at": ts,
                "status": status, "model": model, "output": output or [],
                "error": None, "incomplete_details": None,
                "instructions": body.get("instructions"),
                "usage": u, "metadata": {}}

    if not stream:
        think_buf = []
        try:
            full, model_seen, usage, acc_name, tc = await asyncio.to_thread(
                infer_with_pool, messages, model, tools, None,
                (think_buf.append if REASONING else None), None, "responses",
                temp, tp)
        except DeepError as e:
            raise HTTPException(502, f"devin error: {e.code}: {e.message}") from e
        except (ConnectionError, RuntimeError) as e:
            raise HTTPException(503, f"pool unavailable: {e}") from e
        u = usage_of(usage)
        output = []
        if think_buf:
            output.append({"type": "reasoning", "id": f"rs_{uuid.uuid4().hex[:24]}",
                           "summary": [{"type": "summary_text",
                                        "text": "".join(think_buf)}]})
        if full:
            output.append({"type": "message", "id": f"msg_{uuid.uuid4().hex[:24]}",
                           "role": "assistant", "status": "completed",
                           "content": [{"type": "output_text", "text": full,
                                        "annotations": []}]})
        for t in tc:
            output.append({"type": "function_call",
                           "id": f"fc_{uuid.uuid4().hex[:24]}",
                           "call_id": t["id"], "name": t["name"],
                           "arguments": json.dumps(t["input"],
                                                   ensure_ascii=False),
                           "status": "completed"})
        resp = base_response("completed", output, {
            "input_tokens": u["prompt_tokens"],
            "output_tokens": u["completion_tokens"],
            "total_tokens": u["total_tokens"],
            "output_tokens_details": {"reasoning_tokens": 0}})
        return JSONResponse(resp, headers={"x-devin-account": acc_name})

    async def sse():
        job = StreamJob(messages, model, tools, source="responses",
                        temperature=temp, top_p=tp)
        out_idx = 0
        think_state = {"open": False, "id": None}
        msg_state = {"open": False, "id": None}

        def ev(etype, payload):
            data = {"type": etype, **payload}
            return f"event: {etype}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

        try:
            yield ev("response.created", {"response": base_response()})
            yield ev("response.in_progress", {"response": base_response()})
            async for kind, val in job.chunks():
                if kind == "thinking":
                    if not think_state["open"]:
                        think_state["open"] = True
                        think_state["id"] = f"rs_{uuid.uuid4().hex[:24]}"
                        yield ev("response.output_item.added", {
                            "output_index": out_idx,
                            "item": {"type": "reasoning",
                                     "id": think_state["id"], "summary": []}})
                    yield ev("response.reasoning_summary_text.delta", {
                        "item_id": think_state["id"], "output_index": out_idx,
                        "delta": val})
                elif kind == "delta":
                    if think_state["open"]:
                        yield ev("response.output_item.done", {
                            "output_index": out_idx,
                            "item": {"type": "reasoning",
                                     "id": think_state["id"],
                                     "summary": [{"type": "summary_text",
                                                  "text": ""}]}})
                        out_idx += 1
                        think_state["open"] = False
                    if not msg_state["open"]:
                        msg_state["open"] = True
                        msg_state["id"] = f"msg_{uuid.uuid4().hex[:24]}"
                        yield ev("response.output_item.added", {
                            "output_index": out_idx,
                            "item": {"type": "message", "id": msg_state["id"],
                                     "role": "assistant", "status": "in_progress",
                                     "content": []}})
                        yield ev("response.content_part.added", {
                            "item_id": msg_state["id"], "output_index": out_idx,
                            "content_index": 0,
                            "part": {"type": "output_text", "text": "",
                                     "annotations": []}})
                    yield ev("response.output_text.delta", {
                        "item_id": msg_state["id"], "output_index": out_idx,
                        "content_index": 0, "delta": val})
                elif kind == "tool_use":
                    pass  # 聚合到 done 统一发
                elif kind == "done":
                    if msg_state["open"]:
                        full_text = val.get("full", "")
                        yield ev("response.output_text.done", {
                            "item_id": msg_state["id"], "output_index": out_idx,
                            "content_index": 0, "text": full_text})
                        yield ev("response.output_item.done", {
                            "output_index": out_idx,
                            "item": {"type": "message", "id": msg_state["id"],
                                     "role": "assistant", "status": "completed",
                                     "content": [{"type": "output_text",
                                                  "text": full_text,
                                                  "annotations": []}]}})
                        out_idx += 1
                        msg_state["open"] = False
                    output = []
                    if think_state["id"]:
                        output.append({"type": "reasoning",
                                       "id": think_state["id"], "summary": []})
                    if val.get("full"):
                        output.append({"type": "message",
                                       "id": msg_state["id"]
                                       or f"msg_{uuid.uuid4().hex[:24]}",
                                       "role": "assistant", "status": "completed",
                                       "content": [{"type": "output_text",
                                                    "text": val["full"],
                                                    "annotations": []}]})
                    for t in val.get("tool_calls", []):
                        fcid = f"fc_{uuid.uuid4().hex[:24]}"
                        item = {"type": "function_call", "id": fcid,
                                "call_id": t["id"], "name": t["name"],
                                "arguments": json.dumps(t["input"],
                                                        ensure_ascii=False),
                                "status": "completed"}
                        output.append(item)
                        yield ev("response.output_item.added", {
                            "output_index": out_idx,
                            "item": {"type": "function_call", "id": fcid,
                                     "call_id": t["id"], "name": t["name"],
                                     "arguments": "", "status": "in_progress"}})
                        yield ev("response.function_call_arguments.delta", {
                            "item_id": fcid, "output_index": out_idx,
                            "delta": item["arguments"]})
                        yield ev("response.function_call_arguments.done", {
                            "item_id": fcid, "output_index": out_idx,
                            "arguments": item["arguments"]})
                        yield ev("response.output_item.done", {
                            "output_index": out_idx, "item": item})
                        out_idx += 1
                    u = usage_of(val.get("usage", {}))
                    final = base_response("completed", output, {
                        "input_tokens": u["prompt_tokens"],
                        "output_tokens": u["completion_tokens"],
                        "total_tokens": u["total_tokens"],
                        "output_tokens_details": {"reasoning_tokens": 0}})
                    yield ev("response.completed", {"response": final})
                else:
                    yield ev("response.failed", {
                        "response": {**base_response("failed"),
                                     "error": {"code": "upstream_error",
                                               "message": str(val)}}})
        finally:
            job.cancel()

    return StreamingResponse(with_heartbeat(sse()),
                             media_type="text/event-stream")


# ---------------------------------------------------------------- 管理面板

ADMIN_HTML = """<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<title>devin-gateway 控制台</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--fg:#e6edf3;--dim:#8b949e;
--ok:#3fb950;--bad:#f85149;--warn:#d29922;--acc:#58a6ff}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui;margin:0;padding:20px}
h1{font-size:18px;margin:0 0 4px} .sub{color:var(--dim);font-size:12px;margin-bottom:16px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:12px}
.card .k{color:var(--dim);font-size:12px}.card .v{font-size:22px;font-weight:600}
.card .v.ok{color:var(--ok)}.card .v.bad{color:var(--bad)}
h2{font-size:14px;color:var(--acc);margin:20px 0 8px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--bd);border-radius:8px;overflow:hidden}
th,td{padding:6px 10px;border-bottom:1px solid var(--bd);text-align:left;font-size:13px}
th{color:var(--dim);font-weight:500;background:#1c2128}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.g{background:var(--ok)}.r{background:var(--bad)}.y{background:var(--warn)}
button{background:#21262d;color:var(--fg);border:1px solid var(--bd);border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px}
button:hover{background:#30363d}.btn-red{color:var(--bad)}.btn-green{color:var(--ok)}
textarea{width:100%;background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:8px;padding:10px;min-height:70px;font:inherit}
.ans{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:10px;margin-top:8px;white-space:pre-wrap;min-height:20px}
.meta{color:var(--dim);font-size:12px;margin-top:4px}
.row{display:flex;gap:8px;margin-top:8px;align-items:center}
.err{color:var(--bad)}
@media(max-width:720px){.grid{grid-template-columns:repeat(2,1fr)}}
</style></head><body>
<h1>devin-gateway 控制台</h1>
<div class="sub" id="sub">loading…</div>

<div class="grid">
 <div class="card"><div class="k">总请求</div><div class="v" id="s-total">–</div></div>
 <div class="card"><div class="k">成功</div><div class="v ok" id="s-ok">–</div></div>
 <div class="card"><div class="k">失败</div><div class="v bad" id="s-fail">–</div></div>
 <div class="card"><div class="k">Tokens 进/出</div><div class="v" id="s-tok" style="font-size:16px">–</div></div>
 <div class="card"><div class="k">可用账号</div><div class="v" id="s-acc">–</div></div>
 <div class="card"><div class="k">运行时长</div><div class="v" id="s-up" style="font-size:16px">–</div></div>
</div>

<h2>账号池 <button onclick="egress()">实测出口 IP</button> <button onclick="reloadPool()">重载配置</button></h2>
<table id="acc"><thead><tr>
<th>状态</th><th>账号</th><th>代理</th><th>inflight</th><th>总/成功/失败</th>
<th>tokens 进/出</th><th>配额 日/周</th><th>冷却</th><th>拒绝模型</th><th>最近错误</th><th>操作</th>
</tr></thead><tbody></tbody></table>

<h2>快速试跑</h2>
<textarea id="prompt" placeholder="输入测试 prompt…">Reply with exactly one word: pong</textarea>
<div class="row"><button onclick="testChat()">发送 (自动选号)</button>
<select id="model"><option value="">默认模型</option></select>
<span class="meta" id="test-meta"></span></div>
<div class="ans" id="test-ans">—</div>

<h2>最近请求 (50)</h2>
<table><thead><tr><th>时间</th><th>来源</th><th>账号</th><th>模型</th><th>状态</th><th>tokens</th><th>耗时</th><th>错误</th></tr></thead>
<tbody id="req"></tbody></table>

<script>
const $=id=>document.getElementById(id);
async function j(url,opt){const r=await fetch(url,opt);return r.json()}
async function refresh(){
  try{
    const d=await j('/admin/api/overview');
    const s=d.stats;
    $('s-total').textContent=s.total; $('s-ok').textContent=s.ok; $('s-fail').textContent=s.fail;
    $('s-tok').textContent=s.prompt_tokens+' / '+s.completion_tokens;
    const up=Math.floor(s.uptime_s);
    $('s-up').textContent=(up>=3600?Math.floor(up/3600)+'h ':'')+(up%3600>=60?Math.floor(up%3600/60)+'m':up+'s');
    $('s-acc').textContent=d.pool.accounts.filter(a=>a.available).length+'/'+d.pool.accounts.length;
    $('sub').textContent='mode='+d.mode+' · strategy='+d.pool.strategy+' · models='+(d.models.join(','));
    const tb=$('acc').querySelector('tbody'); tb.innerHTML='';
    for(const a of d.pool.accounts){
      const st=a.available?(a.enabled?'<span class="dot g"></span>正常':'<span class="dot y"></span>停用'):'<span class="dot r"></span>不可用';
      const cd=a.cooldown_left_s>0?a.cooldown_left_s+'s':'-';
      const dm=a.denied_models.length?a.denied_models.join(','):'-';
      const le=a.last_err?('<span class="err">'+a.last_err.slice(0,50)+'</span>'):'-';
      const btn=a.enabled?`<button class="btn-red" onclick="acc('${a.name}','disable')">停用</button>`
                         :`<button class="btn-green" onclick="acc('${a.name}','enable')">启用</button>`;
      tb.insertAdjacentHTML('beforeend',`<tr><td>${st}</td><td>${a.name}</td><td>${a.proxy||'直连'}</td>
      <td>${a.inflight}</td><td>${a.total}/${a.ok}/${a.fail}</td>
      <td>${a.prompt_tokens}/${a.completion_tokens}</td><td>${a.daily_pct!=null?a.daily_pct+'% / '+(a.weekly_pct??'-')+'%':'-'}</td><td>${cd}</td><td>${dm}</td><td>${le}</td><td>${btn}</td></tr>`);
    }
    const rq=$('req'); rq.innerHTML='';
    for(const r of d.recent){
      rq.insertAdjacentHTML('beforeend',`<tr><td>${r.ts}</td><td>${r.source}</td><td>${r.account}</td>
      <td>${r.model}</td><td>${r.ok?'<span class="dot g"></span>ok':'<span class="dot r"></span>fail'}</td>
      <td>${r.pt}/${r.ct}</td><td>${r.ms}ms</td><td class="err">${r.err||''}</td></tr>`);
    }
  }catch(e){$('sub').textContent='refresh error: '+e}
}
async function acc(name,act){await j('/pool/'+name+'/'+act,{method:'POST'});refresh()}
async function reloadPool(){await j('/pool/reload',{method:'POST'});refresh()}
async function egress(){
  const d=await j('/pool/egress');
  alert(Object.entries(d.egress).map(([k,v])=>k+' → '+v).join('\\n'));
}
async function testChat(){
  $('test-meta').textContent='…';
  try{
    const d=await j('/admin/api/test_chat',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({prompt:$('prompt').value,model:$('model').value||null})});
    $('test-ans').textContent=d.answer||d.error||'(空)';
    $('test-meta').textContent='账号='+d.account+' · '+d.ms+'ms · tokens '+d.prompt_tokens+'/'+d.completion_tokens;
  }catch(e){$('test-ans').textContent='ERROR: '+e}
  refresh();
}
(async()=>{
  const d=await j('/v1/models');
  const sel=$('model'); d.data.forEach(m=>{const o=document.createElement('option');o.value=o.textContent=m.id;sel.appendChild(o)});
})();
refresh(); setInterval(refresh,4000);
</script></body></html>"""


@app.get("/admin")
async def admin_page():
    from fastapi.responses import HTMLResponse
    return HTMLResponse(ADMIN_HTML)


@app.get("/admin/api/overview")
async def admin_overview():
    return {"mode": "deep-v4-tools", "stats": {
                **STATS, "uptime_s": round(time.time() - STATS["start"])},
            "pool": POOL.snapshot(), "models": MODELS,
            "recent": list(RECENT)}


@app.post("/admin/api/test_chat")
async def admin_test_chat(request: Request):
    check_auth(request)
    body = await request.json()
    prompt = body.get("prompt", "ping")
    model = pick(body.get("model"))
    msgs = [{"uuid": str(uuid.uuid4()), "role": ROLE_USER, "content": prompt}]
    t0 = time.time()
    try:
        full, model_seen, usage, acc_name, tc = await asyncio.to_thread(
            infer_with_pool, msgs, model, None, None, None, None, "admin")
        return {"answer": full, "account": acc_name, "model": model_seen,
                "ms": round((time.time() - t0) * 1000),
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0)}
    except DeepError as e:
        return {"error": f"{e.code}: {e.message}", "ms": round((time.time() - t0) * 1000)}
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}", "ms": round((time.time() - t0) * 1000)}
