# Devin CLI 协议逆向笔记

> 目标版本: devin CLI `3000.11.3` (Rust, 内部代号 `chisel`, 仓库 `devin-rs`, API 客户端 crate `windsurf-api-client`, agent 代号 `affogato`)
> 全部结论来自二进制 strings + 内嵌文档 + mitmproxy 流量捕获 + 活体差分测试, 均经实测验证。

## 1. 发行与分发

- 安装器 `https://cli.devin.ai/install.sh`, manifest `https://static.devin.ai/cli/current/manifest.json`
- manifest 结构 `{"version", "platforms":{triple:{url,sha256}}}`; musl/gnu 为别名 (6 个真实制品)
- 三个公开渠道 (devin.ai / devinenterprise.com / windsurf.com) 制品 **sha256 完全相同**, 仅 CDN 域名与 `distribution` 标记不同; federal/portal 渠道 manifest 403 (鉴权门控)

## 2. 认证链

```
devin auth login
  → PKCE (S256): GET app.devin.ai/auth/cli/continue?state&code_challenge&cli_pkce_marker=1
  → 浏览器登录 (邮箱 OTP) → 页面显示一次性 CLI code (5min)
  → POST https://api.devin.ai/auth/cli/token          ← 普通 REST, 非 ConnectRPC
       {"code": "<cli_code>", "code_verifier": "<pkce_verifier>"}
  → 200 {"token": "<JWT>", "webapp_host": "app.devin.ai"}
```

- JWT: HS256, payload **仅** `{"session_id": "windsurf-session-<uuid>"}`, **无 exp/iat** —
  无客户端刷新流程, 有效期由服务端会话控制
- 存储: `credentials.toml` 的 `windsurf_api_key = "devin-session-token$<JWT>"` (**前缀是值的一部分**)
- 后续所有 API: `Authorization: Basic <windsurf_api_key 原样>` (Basic 包 `keyid$secret` 惯例)

## 3. RPC 传输

- 认证业务主机: `https://server.codeium.com` (api.devin.ai 只管 token 交换/云侧)
- 编解码: ConnectRPC
  - 一元 RPC: `content-type: application/proto`
  - 服务端流: `content-type: application/connect+proto`, 帧 = `flag(1B) + len_be32(4B) + proto`,
    尾帧 flag=2 为 JSON trailer (`{}` = 成功, 错误为 `{"error":{"code","message"}}`)

## 4. GetChatMessage (推理, 服务端流)

`POST /exa.api_server_pb.ApiServerService/GetChatMessage`

### 请求 (顶层字段, 实测最小必需集 **{1, 3, 7, 21}**)

| field | 类型 | 含义 | 必需 |
|---|---|---|---|
| 1 | msg client_info | `{1:"chisel",2:版本,3:auth,4:"en",5:"windows",7:版本,12:"chisel",31:指纹hex}` | ✅ (缺→invalid_argument) |
| 2 | bytes | 环境上下文 (CLI 的 system_info 前置块) | ❌ |
| 3 | repeated msg | 消息 `{1:uuid, 2:role, 3:content, 6:tool_call, 7/11:占位}` | ✅ |
| 7 | varint | 值 5 (来源枚举) | ✅ (缺→failed_precondition) |
| 8 | msg completion_config | `{1:1, 2:128000, 3:400, 5:temperature(f64), 7:top_k, 8:top_p(f64)}` | ❌ (但**一旦带上 f8 必填**) |
| 10 | repeated tool | `{1:name, 2:description, 3:input_schema JSON 字符串}` | ❌ |
| 15 | msg | `{1:uuid, 3:4, 4:14}` 会话上下文 | ❌ |
| 16 | string(36) | harness uuid | ❌ |
| 20 | varint 1 | is_user_initiated | ❌ |
| 21 | string | **模型名** (路由键, 服务端按套餐鉴权) | ✅ |
| 28 | string | 会话标签 | ❌ |

**消息角色**: `1`=用户文本 · `2`=assistant(文本 content 或工具调用 field6 `{1:call_id,2:name,3:args_json}`, 尾随空 field11) · `4`=工具结果 (content=`Tool '<name>' output: …`, 尾随空 field7)

**completion_config 怪癖 (实测)**:
- f5/f8 是 f64 (**wiretype 1**), f3 不是 max_output_tokens (400 vs 8000 输出相同)
- **f8 缺失 → invalid_argument**
- **temperature=0.0 → invalid_argument** (0.001 可), 网关钳位 0.01

### 响应流 (逐帧)

| field | 含义 |
|---|---|
| 1 | message_id (`bot-<uuid>`) |
| 2 | Timestamp `{1:sec, 2:nanos}` |
| 3 | **答案文本增量** |
| 5 | 分段结束标记 |
| 6 | **工具调用流**: `{1:call_id, 2:name, 3:args_json 增量}` (OpenAI function-call 语义) |
| 7 | 元数据 `{2:prompt_tokens, 3:completion_tokens, 6:?, 8:{x-request-id…}, 9:model}` |
| 9 | **思维链增量** (与答案分离) |
| 17 | chat uuid |
| 28 | Response Statistics (展示用) |

### 行为怪癖

- **field 31 (client_info 内 732 字符 hex) 不被服务端校验**: 缺失/伪造/跨 RPC 混用全部放行 —
  纯遥测采集, 非机器码绑定 (同一 RPC 内跨请求稳定、重放有效)
- 模型权限按套餐在服务端强制; 无权限模型 → `permission_denied`
- `swe-1-6-fast` → `failed_precondition` (另一类门控)
- 免费档模型有思维链外显倾向 (field 9 大段 reasoning)

## 5. GetUserStatus (配额)

`POST /exa.seat_management_pb.SeatManagementService/GetUserStatus` → 响应 `/1/13` = PlanStatus:

| field | 含义 |
|---|---|
| 1 | 内嵌消息: 计划名(Free/Pro…), org_id, webapp/api host, 团队名, 限速提示 |
| 8/9 | 数值 (2500/500, 疑似速率限制) |
| 14 | **daily_quota_remaining_percent** |
| 15 | **weekly_quota_remaining_percent** |
| 17 | daily_quota_reset_at_unix (UTC 08:00) |
| 18 | period_reset_at_unix |

差分法验证: 两次采样间隔的 14/15 递减量与实际用量吻合。响应内嵌每模型目录 (含 **ACU 单价 f32**),
且目录内容会在数小时内动态增删。

## 6. 服务方法清单 (捕获/识别)

```
exa.api_server_pb.ApiServerService      GetChatMessage*, GetCliModelConfigs, AssignModel,
                                        GetAccountManagedPlugins(+Bundle), Add/RemoveUserManagedPlugin,
                                        GetWebSearchResults, GetImageCaption, SubmitBugReport, …
exa.seat_management_pb.SeatManagementService  GetUserStatus, GetCliTeamSettings,
                                        ExchangePKCEAuthorizationCode, ExchangeDevinCLIPKCECode*, …
exa.product_analytics_pb.ProductAnalyticsService  BatchRecordAnalyticsEvents
(* = 已捕获实测)
```

模型目录 (`GetCliModelConfigs`, 605KB): 数百模型 (`claude-opus-5-5-*`, `claude-fable-5-1-*`,
`gpt-6-sol/astra/luna`, `gemini-3-8-flash`, `glm-5-3`, `kimi-k3`, `deepseek-v4`, `grok-4-7`,
`swe-2-*`, fusion 组合 …), 目录含 `model_name/base_url/max_output_tokens/tokenizer/ACU 成本`,
且**数小时内动态增删**。

## 7. 其他面 (未深挖)

- CLI 携带内置文档 (`share/devin/docs/*.mdx`): proxy/模型/命令说明, 逆向时先读省一半力气
- `ACP_BACKEND=openai` + `OPENAI_API_BASE/KEY` + `USE_COMPLETIONS=true`: CLI 反向接入外部
  OpenAI 兼容后端 (与本网关方向相反)
- `devin acp`: 标准 Agent Client Protocol v1.0 stdio 服务器 (REPL 本体即其客户端)
- Cascade 协议 (Windsurf IDE 的 modelUid 流, 含 `GetCascadeModelConfigs`) — 另一条更重的 agentic 面
- TLS: rustls 只读 OS 证书库 (Windows 忽略 SSL_CERT_FILE); MITM 抓包需把 CA 装入系统库
