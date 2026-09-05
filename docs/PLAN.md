# PLAN · prompt-audit 开发规划

> 素材库 + 规则种子 + 里程碑细则。 README 讲定位，这里讲怎么做。

## 里程碑 M0：dogfood（先扫自己）

目标不是发布，是拿到第一批**真实告警**——所有素材都来自自己的仓库：

| 靶子 | 位置 | 预期发现 |
|---|---|---|
| bounty-guard 的 MCP server 接入配置 | README `mcpServers` JSON 片段 | 规则 1（描述指令话术）的演示场景 |
| InjectArena 五个守阵者 system prompt | `InjectArena/levels/*.json` | 规则 6（高危授权话术）的真实样本 |
| InjectArena guard 钩子关键词 | `levels/*.json` 的 guard 配置 | 与规则 1 短语库的重合度 |
| 本机各项目的 AGENTS.md / CLAUDE.md | 工作目录 | 真实 AI 资产盘点 |

M0 验收标准：对 bounty-guard + InjectArena 各产出一份扫描报告，误报率有数字（沿用每周误报率周报的做法）。

## 规则种子（形态 A，JS/JSON 优先）

| 规则 id | 严重度 | 检测什么 | 正例思路 |
|---|---|---|---|
| `td-injection-phrase` | 高危 | 工具描述里的指令式话术："ignore previous instructions"、"系统提示词"、"不要告诉用户"、Do not reveal… | 短语库直接来自 InjectArena 语料的指令句式，正反用例各配 |
| `td-hidden-unicode` | 高危 | 工具描述里的零宽字符、双向控制符、同形字混淆 | 扫描范围含 `mcp.json` / 工具定义 JSON |
| `td-exfil-pair` | 高危 | 权限爆炸半径：单工具同时声明"读文件/环境变量" + "网络外发"能力 | 描述文本 + 工具 schema 的启发式配对 |
| `mcp-drift` | 中危 | 工具描述 hash 与基线漂移（rug pull：装时无害，更新后投毒） | 基线存 JSON，PR 里 diff hash 变化 |
| `mcp-shadow` | 中危 | 跨 server 同名工具遮蔽 | 解析 `mcp.json` 多 server 配置 |
| `sp-secret-embed` | 高危 | system prompt / AGENTS.md 里硬编码 API key、flag、内部地址 | 复用 bounty-guard `hardcoded-secret`，扩展到 .md/.txt/.json |
| `sp-override-weak` | 中危 | 易被覆盖的高危授权话术："无论用户要求什么都要"、"绝不拒绝"、"跳过所有限制" | 候选规则，M0 dogfood 看误报再定去留 |
| `agent-tool-mismatch` | 低危 | AGENTS.md 声明的能力 vs 实际挂载工具的差集 | v2，需要配置解析，先不做 |

规则设计原则沿用：**宁可漏报不可误报**，每条规则配正反用例；单行豁免注释沿用 `// prompt-audit-ignore`。

## 回归门禁细则（形态 B）

- 引擎：抽 InjectArena `defenseEvaluator.js` + `judge.js`（UMD 纯逻辑）为独立包，强制显式注入 judge——契约不变：引擎无权替换裁判，`matched` 只存服务端内存。
- **diff 驱动语料选择**：改动段落 → 攻击面映射（改了工具相关段 → 只跑 tool-abuse 语料；改了数据出口描述 → 只跑 data-exfiltration）。无映射时默认子集 ≤ 20 条，可配"试跑条数"小样先行（呼应 InjectArena 试考条数）。
- 基线：拦截率基线存 JSON（每攻击面一行），PR 低于基线即红灯；基线只升不降需显式确认，防"把门禁跑低"。
- 成本闸：单 PR 语料条数 × LLM 调用上限硬编码可配；每 IP/每 repo 限流沿用令牌桶。

## 非目标（明确不做）

- 不做全量 AST / 全仓库代码扫描——那是 bounty-guard 和传统 SAST 的事，prompt-audit 只看 AI 层资产。
- 不做运行时拦截代理（LLM 防火墙）——形态后置，先占住开发工作流里的门禁位置。
- 判定/评分永远不用 LLM 当裁判——LLM 本身可被注入，这个攻击面不存在于本工具。

## 技术栈与复用清单

- TypeScript + 零运行时依赖优先（bounty-guard 同栈）。
- 直接可搬的模块：diff 解析器、规则引擎骨架、粘性评论 Action 壳、doctor、MCP server 骨架（bounty-guard）。
- 直接可搬的模块：`judge.js`、`defenseEvaluator.js`、`rateLimiter.js`、`corpus/` schema 与 100 条语料（InjectArena）。
- 发布形态对齐 bounty-guard：npm CLI → GitHub Action → MCP Server → VS Code。

## 搜索与发布清单（SEO）

名字只解决一半，另一半靠元数据把搜索词喂给 npm / GitHub：

- **npm 包名** `prompt-audit`（已确认可用；无连字符 `promptaudit` 同样空闲，发布时建议一并占住防蹭名），CLI 同名：`npx prompt-audit scan`。
- **npm description**（中英关键词都放，npm/GitHub 搜索都索引描述文本）：
  `AI-layer security audit — scan system prompts, MCP configs & tool descriptions for prompt injection and toxic permissions; diff-driven prompt regression gate. AI 层安全审计与门禁：提示注入扫描 / MCP 安全 / prompt 回归测试`
- **npm keywords**：`prompt-injection, prompt-security, prompt-audit, mcp, mcp-security, llm-security, ai-security, agent-security, security-scanner, github-action`
- **GitHub topics**（全小写连字符）：`prompt-injection, prompt-security, mcp-security, llm-security, agent-security, ai-security, security-audit, security-scanner, github-action, owasp`
- **README 首段自然出现搜索短语**：prompt audit / prompt injection scanner / MCP security scanner / 提示注入 / 提示词安全——中英各一遍，不做关键词堆砌。
- **同赛道参照**：GitHub `agent-audit`（★225，静态扫 LLM agent 的注入与 MCP 配置）证明这个搜索位有真实流量；它占 "agent"，我们占 "prompt audit"，靠 topics 在同批搜索里共现，不正面撞名。
- **避开的撞名区**（查证于 2026-09）：npm 已占 `promptscan`（活跃包）、`prompt-inspector`、`mcp-audit`、`llm-audit`；`promptshield`/Azure Prompt Shields、`prompt-guard`/Meta Prompt Guard 是品牌阴影区；GitHub 已有 `prompt-scanner`（★68）、`PromptGuardian`（★4 同赛道）、`prompt-patrol`（3 个同名小项目）、`prompt-radar`（同名小项目）。
