# devincli-gateway

把 Devin CLI 的云端模型账号反向代理为 **OpenAI / Anthropic / OpenAI Responses** 三协议兼容的本地或 VPS 网关。
基于对 Devin CLI (v3000.11.3, Rust) 的完整协议逆向 —— 不依赖 CLI 二进制, 直连云端 ConnectRPC。

> ⚠️ 仅供协议研究与个人自用。使用你的**自己的**账号, 注意目标服务条款与账号风控风险。

## 特性

- **三协议**: `/v1/chat/completions` + `/v1/responses` (OpenAI, 含 function_call/Responses 事件流) + `/v1/messages` (Anthropic, 含 tool_use/thinking)
- **工具调用全映射**: 客户端 `tools[]` ↔ Devin 原生工具协议 (field10/field6), Claude Code 等 agentic 客户端可真正执行本地工具
- **思维链透传**: OpenAI `reasoning_content` / Anthropic `thinking` blocks
- **多账号号池**: round_robin / least_inflight / weighted / failover 四种调度, 按 (账号,模型) 精确熔断, 跨账号自动重试
- **每账号独立出口代理**: HTTP CONNECT / SOCKS5 隧道 (纯 stdlib 手写), 出口 IP 实测端点
- **配额感知**: 定时拉取各账号 日/周配额余量 与重置时间 (GetUserStatus 差分逆向)
- **真实 token 计量**: 服务端 usage 直读 (非估算)
- **Web 控制台**: `/admin` 单页面板 — 统计/账号管理/快速试跑/请求流水, 零额外依赖
- **工程化**: TLS keep-alive 连接池、SSE 心跳、客户端断连即断上游、错误透明透传 (502+trace ID)

## 快速开始

```bash
pip install fastapi uvicorn

# 凭据 (三选一):
#  1) 环境变量  DEVIN_API_KEY="devin-session-token$<JWT>"  DEVIN_API_SERVER_URL="https://server.codeium.com"
#  2) Devin CLI 登录后的 credentials.toml (自动搜索 Win %APPDATA% / Linux ~/.local/share 等)
#  3) accounts.json 多账号号池 (见 accounts.json.example)

python deep_gateway.py            # 或 uvicorn deep_gateway:app --port 8788
# 浏览器打开 http://127.0.0.1:8788/admin
```

### 获取凭据

安装 [Devin CLI](https://cli.devin.ai/install.sh) 后 `devin auth login`, 凭据自动落在
`credentials.toml` (字段 `windsurf_api_key` 即 `devin-session-token$<JWT>` 整串)。
或使用 [`tools/login_driver.py`](tools/) 自动化登录并导出。

### 客户端接入

```bash
# OpenAI 系 (含 Codex CLI —— 自动适配 /v1/responses)
export OPENAI_BASE_URL=http://127.0.0.1:8788/v1

# Claude Code / Anthropic 系
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788
export ANTHROPIC_MODEL=swe-1-6-slow
```

## 号池配置

```json
{
  "strategy": "least_inflight",
  "max_attempts": 3,
  "accounts": [
    {"name": "acc1",
     "api_key": "devin-session-token$<JWT>",
     "api_server_url": "https://server.codeium.com",
     "proxy": "socks5://user:pass@PROXY_HOST:PORT",
     "weight": 1}
  ]
}
```

调度策略 / 熔断语义 / 管理端点 (`/pool/*`) 详见 [deploy/README_DEPLOY.md](deploy/README_DEPLOY.md)。

## 协议逆向文档

对 Devin CLI (Rust, 内部代号 chisel) 的完整协议还原, 见 **[docs/PROTOCOL.md](docs/PROTOCOL.md)**:
认证链 (PKCE→JWT)、ConnectRPC+protobuf 帧格式、GetChatMessage 请求/流式响应字段级 schema、
消息角色 (role1/2/4)、工具协议 (field10/field6)、配额结构 (PlanStatus)、以及实测的行为怪癖
(temperature=0 被拒、f8 必填、指纹不校验等)。

## VPS 部署

见 [deploy/README_DEPLOY.md](deploy/README_DEPLOY.md) (systemd + 安全建议 + Claude Code 接入)。

## 已知限制

- 可用模型由 Devin 套餐决定 (免费档实测仅 `swe-1-6-slow`), 请求无权限模型返回 502
- temperature=0 会被钳位为 0.01 (服务端拒绝 0.0)
- max_output_tokens 不可控 (服务端字段未开放)
- 会话 token 无过期时间 (服务端会话控制), 失效需重新 `devin auth login`

## License

[MIT](LICENSE)
