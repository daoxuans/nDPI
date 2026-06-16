# nDPI AI 流量检测能力扩展 — 产品需求文档

> **版本**: v1.0  
> **日期**: 2026-06-16  
> **基线**: 7b43393d8a36cf71b61f582093b1185c4ed0b0b9  
> **涉及提交**: 6 commits (d836f8880 .. a7635ac0a)  
> **变更范围**: 11 files, +998 lines

---

## 1. 背景与目标

### 1.1 背景

随着大语言模型（LLM）与 AI 推理基础设施的爆发式增长，企业网络中出现大量 AI 相关流量。现有 nDPI 对 AI 流量的识别能力仅覆盖 9 个域名（OpenAI、ChatGPT、DeepSeek、Claude、Gemini 等），且缺乏对 AI 推理服务器协议（MCP、Ollama、Triton、vLLM）的深度包检测能力。

### 1.2 目标

本需求旨在将 nDPI 打造为业界最全面的 AI 流量检测引擎，覆盖三个维度：

| 维度 | 目标 |
|------|------|
| **域名识别** | 从 9 扩展到 ~100 个 AI 服务域名，覆盖七大子类别 |
| **协议识别** | 新增 4 种 AI 推理服务器协议的 DPI 检测 |
| **元数据提取** | 从协议流量中提取结构化元数据（模型名、API 动作等）并支持 JSON 序列化 |

---

## 2. 功能需求

### 2.1 AI/LLM 域名分类扩展

#### 2.1.1 概述

在 `ndpi_content_match.c.inc` 的分类匹配表中，将 `ARTIFICIAL_INTELLIGENCE` 类别的域名从原有 9 个扩展到约 100 个，按子类别组织。

#### 2.1.2 子类别与覆盖范围

| 子类别 | 域名数量 | 覆盖范围 |
|--------|---------|----------|
| AI Chat / 网页对话 | 7 | ChatGPT, Claude, DeepSeek, Perplexity, Gemini, NotebookLM |
| AI API / 开发者平台 | 3 | Anthropic API, Google Gemini API, Google AI Studio |
| AI 模型托管 / 推理 | 8 | HuggingFace, Replicate, Together, Groq, Anyscale, Modal, Banana |
| AI 平台 / 云 AI | 4 | Mistral, Cohere, Databricks, Stability AI |
| AI 编程助手 | 9 | Cursor, Codeium, Sourcegraph, GitHub Copilot, Continue, Tabnine, Supermaven, Windsurf, Bolt, Lovable |
| AI 图像生成 | 2 | Midjourney, Leonardo AI |
| AI 搜索 | 2 | You.com, Kagi |
| 中国 AI 服务 | 26 | 月之暗面/Kimi, 智谱/GLM, 百川, MiniMax, 阶跃星辰, 零一万物, 豆包/火山引擎/方舟, 通义千问/百炼, 百度千帆/一言, 腾讯混元, 讯飞星火, 商汤, Skywork, 小米/Vivo AI, Trae, CodeBuddy, WorkBuddy 等 |
| 国际 AI（额外） | 7 | Meta AI, xAI/Grok, SambaNova, Fireworks |
| AI API 聚合/代理 | ~30 | OpenRouter, Portkey, Helicone, LiteLLM, SiliconFlow, CloseAI-Proxy, API2D, GPTAPI, DashScope 等 |

#### 2.1.3 技术实现

- 所有域名均通过 `ndpi_domain_classify_hostname()` 实现子域名自动匹配（例如 `api.openai.com` 自动匹配 `openai.com` 规则）
- 单元测试覆盖：对 `openai.com`、`api.openai.com`、`claude.ai`、`anthropic.com`、`mistral.ai`、`moonshot.cn` 进行域名分类验证

#### 2.1.4 验收标准

- [ ] `openai.com` 及其子域名被正确分类为 `ARTIFICIAL_INTELLIGENCE`
- [ ] 中国 AI 服务域名（`moonshot.cn`, `zhipuai.cn`, `doubao.com` 等）被正确分类
- [ ] AI 编程助手域名（`githubcopilot.com`, `cursor.sh` 等）被正确分类
- [ ] AI API 代理/聚合域名被正确分类
- [ ] 已有单元测试全部通过

---

### 2.2 MCP（Model Context Protocol）协议检测

#### 2.2.1 协议概述

MCP 是 Anthropic 发布的模型上下文协议，基于 JSON-RPC 2.0，用于 AI 模型与外部工具之间的标准化通信。传输层使用 HTTP POST，响应采用 SSE 流式传输。

#### 2.2.2 检测策略

采用三层递进式检测机制：

| 检测层 | 方法 | 可靠性 |
|--------|------|--------|
| **L1: Header 检测** | 检查 HTTP 请求头中的 `Mcp-Session-Id` 字段 | ⭐⭐⭐ 最高（MCP 独有特征） |
| **L2: URL 路径检测** | 检查 URL 路径包含 `/mcp` 且 Content-Type 为 JSON | ⭐⭐ 较高 |
| **L3: JSON Body 检测** | 检查 JSON body 中是否包含 MCP 特有方法名 | ⭐ 补充（辅助 TCP 原始流检测） |

#### 2.2.3 MCP 方法名列表

支持的 MCP 方法名检测：
- `initialize` — 会话初始化
- `tools/list` — 列出可用工具
- `tools/call` — 调用工具
- `resources/list` — 列出资源
- `resources/read` — 读取资源
- `prompts/list` — 列出提示模板
- `prompts/get` — 获取提示模板
- `notifications/initialized` — 初始化完成通知
- `notifications/cancelled` — 取消通知
- `notifications/progress` — 进度通知
- `notifications/message` — 消息通知

#### 2.2.4 协议分类

- **类别**: `ARTIFICIAL_INTELLIGENCE`
- **协议名**: `MCP`
- **传输**: 明文 TCP / HTTP 子协议
- **默认端口**: 无固定端口（HTTP 子协议）

#### 2.2.5 验收标准

- [ ] HTTP 请求携带 `Mcp-Session-Id` 头时被正确识别为 MCP
- [ ] HTTP POST 到 `/mcp` 路径且 Content-Type 为 JSON 时被识别为 MCP
- [ ] 原始 TCP 流中包含 MCP 方法名和 JSON-RPC 结构时被识别为 MCP
- [ ] 不应将普通 JSON-RPC 调用误识别为 MCP

---

### 2.3 Ollama 推理服务器检测

#### 2.3.1 协议概述

Ollama 是本地 LLM 推理服务器，提供 REST API（兼容 OpenAI API 格式），默认监听端口 11434。

#### 2.3.2 检测策略

采用两层检测机制：

| 检测层 | 方法 | 可靠性 |
|--------|------|--------|
| **L1: HTTP Response** | 检查响应 body 是否包含 `"Ollama is running"` | ⭐⭐⭐ 最高 |
| **L2: URL 路径** | 检查 URL 路径是否匹配 `/api/*` 模式 | ⭐⭐ 较高 |

#### 2.3.3 协议分类

- **类别**: `ARTIFICIAL_INTELLIGENCE`
- **协议名**: `Ollama`
- **传输**: HTTP 子协议 / 原始 TCP
- **默认端口**: `11434` (TCP)

#### 2.3.4 验收标准

- [ ] Ollama 服务器健康检查响应被正确识别
- [ ] `/api/chat`、`/api/generate`、`/api/tags` 等 API 调用被正确识别
- [ ] 端口 11434 上的流量默认检测为 Ollama

---

### 2.4 NVIDIA Triton 推理服务器检测

#### 2.4.1 协议概述

NVIDIA Triton Inference Server 是 NVIDIA 的企业级 AI 推理服务器，遵循 KServe v2 协议标准，默认监听端口 8000（HTTP）和 8001（gRPC）。

#### 2.4.2 检测策略

采用“弱信号 + 强信号确认”的分层检测机制：

| 检测层 | 方法 | 可靠性 |
|--------|------|--------|
| **L1: 强特征（首选）** | 检查响应 body 是否包含 `"server_id":"triton"` | ⭐⭐⭐ 最高 |
| **L2: 强特征（补充）** | 检查服务端元数据/头部是否出现 Triton 明确标识（如 `name=triton` 且包含版本/扩展信息，或 `Server` 头含 triton） | ⭐⭐⭐ 高 |
| **L3: 弱特征** | URL 命中 `/v2/*` KServe 标准路径，仅作为候选信号，不单独定类 | ⭐ 低 |

**防误报原则**：`/v2/*` 属于 KServe 通用路径，不能单独作为 Triton 判定依据；需至少一个强特征确认后再分类为 Triton。

#### 2.4.3 协议分类

- **类别**: `ARTIFICIAL_INTELLIGENCE`
- **协议名**: `NVIDIA_Triton`
- **传输**: HTTP 子协议 / 原始 TCP
- **默认端口**: `8000`, `8001` (TCP)

#### 2.4.4 验收标准

- [ ] Triton 服务器健康检查（`/v2/health/ready`）在强特征确认后被正确识别
- [ ] Triton 模型推理请求（`/v2/models/{name}/infer`）在强特征确认后被正确识别
- [ ] 端口 8000/8001 上流量支持候选识别，但最终定类需强特征确认
- [ ] 不应将普通 KServe 服务误识别为 Triton（`/v2/*` 不可单独触发 Triton 定类）
- [ ] 对不含 `server_id` 的 Triton 变体，支持通过其他强特征（元数据/Server 头）识别

---

### 2.5 vLLM 推理服务器检测

#### 2.5.1 协议概述

vLLM 是高性能开源 LLM 推理引擎，提供 OpenAI 兼容 API（`/v1/*` 路径），默认监听端口 8000。

#### 2.5.2 检测策略

采用两层检测机制：

| 检测层 | 方法 | 可靠性 |
|--------|------|--------|
| **L1: HTTP Response** | 检查响应 body 是否包含 `"vllm"` 关键词 | ⭐⭐⭐ 最高 |
| **L2: URL 路径** | 检查 URL 路径是否匹配 `/v1/*` OpenAI 兼容路径，并排除 OpenAI 官方主机 | ⭐⭐ 较高 |

**防误报措施**: 在 URL 路径检测时，排除已知 OpenAI 官方主机（如 `api.openai.com`），避免将 OpenAI 官方 API 流量误识别为 vLLM。

#### 2.5.3 协议分类

- **类别**: `ARTIFICIAL_INTELLIGENCE`
- **协议名**: `vLLM`
- **传输**: HTTP 子协议 / 原始 TCP
- **默认端口**: `8000` (TCP)

#### 2.5.4 验收标准

- [ ] vLLM 服务器响应被正确识别（响应 body 含 `"vllm"`）
- [ ] vLLM OpenAI 兼容 API 调用（`/v1/chat/completions`）被正确识别
- [ ] OpenAI 官方 API 流量（`api.openai.com`）不被误识别为 vLLM
- [ ] 端口 8000 上的流量默认检测为 vLLM（与 Triton 共享端口时需进一步区分）

---

### 2.6 元数据提取与序列化

#### 2.6.1 概述

为 4 种 AI 协议实现流量元数据的结构化提取和 JSON 序列化能力，便于上层分析系统（SIEM、可观测性平台）消费。

#### 2.6.2 各协议元数据字段

**MCP 协议** (`ndpi_flow_struct.protos.mcp`):

| 字段 | 类型 | 说明 | 示例 |
|------|------|------|------|
| `method` | char[32] | MCP 方法名 | `"tools/call"`, `"initialize"` |
| `tool_name` | char[64] | MCP 工具名 | `"filesystem"`, `"web_search"` |
| `session_id` | char[48] | Mcp-Session-Id 值 | `"abc123-def456"` |
| `protocol_version` | char[12] | 协议版本 | `"2024-11-05"` |

**Ollama 协议** (`ndpi_flow_struct.protos.ollama`):

| 字段 | 类型 | 说明 | 示例 |
|------|------|------|------|
| `api_action` | char[32] | API 动作 | `"chat"`, `"generate"`, `"tags"`, `"pull"`, `"push"` |
| `model_name` | char[64] | 模型名 | `"llama3:70b"`, `"mistral"` |
| `http_method` | u_int8_t | HTTP 方法 | `0=GET`, `1=POST` |

**Triton 协议** (`ndpi_flow_struct.protos.nvidia_triton`):

| 字段 | 类型 | 说明 | 示例 |
|------|------|------|------|
| `endpoint` | char[64] | API 端点 | `"/v2/health/ready"`, `"/v2/models/llama3/infer"` |
| `model_name` | char[64] | 模型名 | `"llama3"`, `"bert-base"` |
| `server_version` | char[12] | Triton 服务器版本 | `"2.42.0"` |

**vLLM 协议** (`ndpi_flow_struct.protos.vllm`):

| 字段 | 类型 | 说明 | 示例 |
|------|------|------|------|
| `api_action` | char[32] | API 动作 | `"chat/completions"`, `"completions"`, `"embeddings"` |
| `model_name` | char[64] | 请求 body 中的 model 字段 | `"meta-llama/Llama-3-70b"` |

#### 2.6.3 JSON 序列化

在 `ndpi_dpi2json()` 中新增 4 个 `case` 分支，输出示例：

```json
{
  "mcp": {
    "method": "tools/call",
    "tool": "web_search",
    "session_id": "abc123",
    "protocol_version": "2024-11-05"
  }
}
```

```json
{
  "ollama": {
    "action": "chat",
    "model": "llama3:70b",
    "method": "POST"
  }
}
```

```json
{
  "triton": {
    "endpoint": "/v2/models/llama3/infer",
    "model": "llama3",
    "version": "2.42.0"
  }
}
```

```json
{
  "vllm": {
    "action": "chat/completions",
    "model": "meta-llama/Llama-3-70b"
  }
}
```

#### 2.6.4 验收标准

- [ ] MCP 流量元数据可正确提取并序列化为 JSON
- [ ] Ollama 流量元数据可正确提取并序列化为 JSON
- [ ] Triton 流量元数据可正确提取并序列化为 JSON
- [ ] vLLM 流量元数据可正确提取并序列化为 JSON
- [ ] 元数据字段为空时不输出对应 JSON key（非空判断）

---

## 3. 技术架构

### 3.1 协议 ID 分配

| 协议 | ID | 类别 |
|------|-----|------|
| `NDPI_PROTOCOL_MCP` | 477 | ARTIFICIAL_INTELLIGENCE |
| `NDPI_PROTOCOL_OLLAMA` | 478 | ARTIFICIAL_INTELLIGENCE |
| `NDPI_PROTOCOL_NVIDIA_TRITON` | 479 | ARTIFICIAL_INTELLIGENCE |
| `NDPI_PROTOCOL_VLLM` | 480 | ARTIFICIAL_INTELLIGENCE |

### 3.2 新增源文件

| 文件 | 描述 |
|------|------|
| `src/lib/protocols/mcp.c` | MCP 协议检测器（247 行） |
| `src/lib/protocols/ollama.c` | Ollama 协议检测器（179 行） |
| `src/lib/protocols/nvidia_triton.c` | NVIDIA Triton 协议检测器（171 行） |
| `src/lib/protocols/vllm.c` | vLLM 协议检测器（155 行） |

### 3.3 修改文件

| 文件 | 变更 |
|------|------|
| `src/include/ndpi_protocol_ids.h` | 新增 4 个协议 ID 枚举值 |
| `src/include/ndpi_typedefs.h` | 新增 4 个协议的 flow struct 存储结构 |
| `src/include/ndpi_private.h` | 声明 4 个 dissector 初始化函数 |
| `src/lib/ndpi_main.c` | 注册 4 个协议的默认配置和 dissector 初始化 |
| `src/lib/ndpi_content_match.c.inc` | 新增 ~90 个 AI 域名分类条目 |
| `src/lib/ndpi_utils.c` | 新增 4 个协议的 JSON 序列化分支 |
| `example/utests.c` | 新增 AI 域名分类单元测试 |

### 3.4 检测架构图

```
                         ┌──────────────────────────┐
                         │  nDPI Detection Engine    │
                         └──────────┬───────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
     ┌────▼────┐             ┌──────▼──────┐           ┌──────▼──────┐
     │ Domain  │             │   HTTP Sub- │           │  Raw TCP    │
     │ Match   │             │   Protocol  │           │  Detection  │
     └────┬────┘             └──────┬──────┘           └──────┬──────┘
          │                         │                         │
          ▼                         ▼                         ▼
 ┌────────────────┐   ┌──────────────────────────┐   ┌────────────────┐
 │ ~100 AI Domains│   │ MCP │ Ollama │ Triton │  │   JSON Body    │
 │ Categorized as │   │     │        │ vLLM   │   │   Pattern      │
 │ ARTIFICIAL_    │   │ Header/URL/Response     │   │   Matching     │
 │ INTELLIGENCE   │   │ based detection          │   │                │
 └────────────────┘   └──────────────────────────┘   └────────────────┘
                                    │
                                    ▼
                         ┌──────────────────────────┐
                         │  Metadata Extraction      │
                         │  (method, model, action,  │
                         │   version, session...)    │
                         └──────────┬───────────────┘
                                    │
                                    ▼
                         ┌──────────────────────────┐
                         │  ndpi_dpi2json()          │
                         │  JSON Serialization       │
                         └──────────────────────────┘
```

---

## 4. 使用场景

| 场景 | 能力 | 价值 |
|------|------|------|
| **企业网络审计** | 识别员工使用的 AI 服务（ChatGPT, Copilot, Cursor 等） | 数据安全治理、合规审计 |
| **AI API 成本分析** | 区分不同 AI 服务商的 API 调用 | FinOps 成本归因 |
| **AI 基础设施监控** | 检测私有化部署的推理服务器（Ollama, Triton, vLLM） | 运维可观测性 |
| **AI 协议审计** | 提取 MCP 工具调用、模型名、协议版本 | 安全审计与合规 |
| **Shadow IT 发现** | 检测未授权的 AI 服务接入 | 安全风险管控 |

---

## 5. 测试要求

### 5.1 单元测试

- [x] AI 域名分类测试（6 个域名 + 子域名匹配）
- [ ] MCP 协议检测测试
- [ ] Ollama 协议检测测试
- [ ] Triton 协议检测测试
- [ ] vLLM 协议检测测试
- [ ] 元数据 JSON 序列化测试

### 5.2 集成测试

- [ ] MCP 流量 pcap 回放测试
- [ ] Ollama 流量 pcap 回放测试
- [ ] Triton 流量 pcap 回放测试
- [ ] vLLM 流量 pcap 回放测试

### 5.3 防误报测试

- [ ] vLLM 与 OpenAI 官方 API 流量区分测试
- [ ] MCP 与普通 JSON-RPC 流量区分测试
- [ ] Triton 与普通 KServe 服务区分测试

---

## 6. 交付清单

| 交付物 | 状态 | 说明 |
|--------|------|------|
| 4 个协议 dissector 源码 | ✅ 已提交 | mcp.c, ollama.c, nvidia_triton.c, vllm.c |
| ~100 个 AI 域名分类 | ✅ 已提交 | ndpi_content_match.c.inc |
| 元数据存储结构 | ✅ 已提交 | ndpi_typedefs.h |
| JSON 序列化支持 | ✅ 已提交 | ndpi_utils.c |
| 协议注册与初始化 | ✅ 已提交 | ndpi_main.c |
| 单元测试 | ✅ 已提交 | utests.c（域名部分） |
| PRD 文档 | ✅ 本文档 | docs/PRD_AI_Traffic_Detection.md |

---

## 7. 附录：完整域名清单

### A. AI Chat / 网页对话
`deepseek.com`, `openai.com`, `chatgpt.com`, `gemini.google.com`, `notebooklm.google.com`, `claude.ai`, `perplexity.ai`

### B. AI API / 开发者平台
`anthropic.com`, `generativelanguage.googleapis.com`, `aistudio.google.com`

### C. AI 模型托管 / 推理
`ollama.com`, `huggingface.com`, `replicate.com`, `together.ai`, `groq.com`, `anyscale.com`, `modal.com`, `banana.dev`

### D. AI 平台 / 云 AI
`mistral.ai`, `cohere.ai`, `databricks.com`, `stability.ai`

### E. AI 编程助手
`cursor.sh`, `codeium.com`, `sourcegraph.com`, `githubcopilot.com`, `continue.dev`, `tabnine.com`, `supermaven.com`, `windsurf.ai`, `bolt.new`, `lovable.dev`

### F. AI 图像生成
`midjourney.com`, `leonardo.ai`

### G. AI 搜索
`you.com`, `kagi.com`

### H. 中国 AI 服务
`moonshot.cn`, `kimi.ai`, `zhipuai.cn`, `bigmodel.cn`, `baichuan-ai.com`, `minimaxi.com`, `stepfun.com`, `yi.com`, `doubao.com`, `volcengine.com`, `ark.cn`, `tongyi.aliyun.com`, `bailian.aliyun.com`, `xiaomimimo.com`, `trae.cn`, `trae.ai`, `ruijie.com.cn`, `vcode-od.vivo.com.cn`, `codebuddy.cn`, `workbuddy.tencent.com`, `qianfan.baidubce.com`, `yiyan.baidu.com`, `hunyuan.tencent.com`, `spark-api.xf-yun.com`, `sensetime.com`, `skywork.com`

### I. 国际 AI（额外）
`meta.ai`, `x.ai`, `sambanova.ai`, `fireworks.ai`

### J. AI API 聚合/代理
`qoder.com`, `qoder.com.cn`, `openrouter.ai`, `portkey.ai`, `helicone.ai`, `litellm.ai`, `siliconflow.cn`, `n1n.ai`, `dmxapi.com`, `link-ai.tech`, `chatany.com`, `closeai-proxy.com`, `ohmygpt.com`, `api2d.com`, `geekapi.ch`, `aiproxy.io`, `gptapi.us`, `gptsapi.net`, `mixchat.org`, `novaapi.com`, `deepapi.net`, `fastapi.ai`, `gpts.vip`, `dashscope.aliyuncs.com`, `minimax.chat`, `hunyuan.tencentcloudapi.com`, `qnaigc.com`, `token173.com`, `catrouter.net`, `poloapi.top`, `openai-proxy.org`, `closeai-asia.com`, `aihubmix.com`, `vveai.com`, `gpt.ge`, `v36.cm`, `lingyaai.cn`, `dmxapi.cn`, `shiyanai.com`, `dataeyes.ai`, `literouter.com`, `apimart.ai`, `vengine.cloud`, `aicvw.com`, `congmingai.com`, `kk9.in`, `tokenriver.ai`, `xlian.top`, `hongtuai.com`, `joyinai.com`, `cognitive.microsoft.com`
