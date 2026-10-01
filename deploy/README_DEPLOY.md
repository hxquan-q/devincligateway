# devin-gateway VPS 部署指南

把本机的 Devin 账号（裸协议网关）部署到 VPS，对 OpenAI / Anthropic 协议客户端提供服务。

## 架构

```
Claude / OpenAI 客户端 ──HTTP──> VPS:8788 (deep_gateway) ──TLS──> server.codeium.com
                                  (systemd 常驻)            还原的 ConnectRPC 协议
```

## 一、打包（在 Windows 本机执行）

```bash
cd E:\devin\capture
mkdir deploy/pkg
copy deep_client.py  deploy\pkg\
copy deep_gateway.py deploy\pkg\
copy ci31.bin        deploy\pkg\          # 客户端指纹 (与登录绑定, 必带)
copy %APPDATA%\devin\credentials.toml deploy\pkg\   # 账号凭据
scp -r deploy\pkg user@VPS:~/devin-pkg
# 同时上传 install.sh / devin-gateway.service
scp deploy\install.sh deploy\devin-gateway.service user@VPS:~/devin-pkg/
```

## 二、安装（在 VPS 执行）

```bash
cd ~/devin-pkg && bash install.sh
# 按提示输入 GATEWAY_API_KEY (对外鉴权口令, 务必设置)
curl http://127.0.0.1:8788/healthz     # → {"ok":true,"mode":"deep-v2",...}
```

凭据两条路任选：
- **文件**：`credentials.toml` + `ci31.bin` 放 `~/.devin/`（install.sh 自动完成）
- **环境变量**：在 service 文件里设 `DEVIN_API_KEY` / `DEVIN_API_SERVER_URL` / `DEVIN_FP_HEX`

## 三、对外暴露（三选一，安全性递减）

1. **SSH 隧道（推荐，零暴露面）**：本地 `ssh -L 8788:127.0.0.1:8788 user@VPS`，
   客户端连 `http://127.0.0.1:8788`
2. **反代 + TLS**：nginx/caddy 反代 8788，配域名证书 + GATEWAY_API_KEY
3. **直开端口**：`--host 0.0.0.0` + 防火墙放行 + **必须** GATEWAY_API_KEY

## 四、接入 Claude

### Claude Code（注意限制，见下）

```bash
export ANTHROPIC_BASE_URL=http://VPS:8788
export ANTHROPIC_AUTH_TOKEN=<GATEWAY_API_KEY>
export ANTHROPIC_MODEL=swe-1-6-slow
claude
```

### 任意 OpenAI 客户端

```bash
export OPENAI_BASE_URL=http://VPS:8788/v1
export OPENAI_API_KEY=<GATEWAY_API_KEY>
```

## 五、必须知道的限制

1. **模型**：账号可用的模型由 Devin 套餐决定。本免费账号实测仅 `swe-1-6-slow`；
   请求其他模型返回 502 permission_denied（透传服务端真实结论）。
2. **Claude Code 的工具调用不支持**：本网关是纯文本补全语义（未映射 Anthropic
   tool_use 块）。Claude Code 能连上并对话，但它依赖工具执行（读写文件/shell），
   纯文本模式下能力大打折扣 —— 适合问答/评审类用法，不适合让它实际改代码。
   需要完整 agentic 能力时，用 Devin 原生 CLI 或带工具的模型 API。
3. **并发**：连接池 16；真正上限是 Devin 服务端对单账号的并发限制（未知，超限会
   502 透传）。
4. **token 过期**：全部请求突然 unauthenticated 时，在本机重跑
   `python capture/login_driver_v4.py` 刷新凭据，重新打包上传（或改用环境变量注入）。
5. **合规**：这是对 Devin 账号协议的逆向网关，非官方 API —— 自用、控制频率，
   注意 Devin 服务条款与账号风控风险。

## 六、运维

```bash
systemctl status devin-gateway
journalctl -u devin-gateway -f          # 日志
systemctl restart devin-gateway
# 性能: warm 请求 ~1-2s (VPS→codeium RTT 决定), 连接池常驻热连接
```
