# Changelog

## 0.1.1（2026-09-08）

M1 规则包收官：7 → 10 条，补上 mcp.json 结构化盲区。npm 上架后首个增量版本。

### 新增规则（3 条）

- `mcp-env-credential`（高危）——MCP server env 内嵌明文凭据。修复 v0.1.0 真实盲区：JSON 形态的 mcp-config 资产只有 obj 没有 text，文本规则对其失效；`OPENAI_API_KEY` 等 env 名不在 secret-field 键名白名单内，「真 key 写进 mcp.json 提交」此前完全漏检。判定双通道：凭据命名 env（排除 `${VAR}` 引用与占位值）+ 值命中强密钥形状（复用 sp-secret-embed 强形状表）
- `mcp-launch-unsafe`（高危/中危）——启动参数/环境关闭安全机制：`--dangerously-skip-permissions` / `--yolo` / `--auto-approve` / `NODE_TLS_REJECT_UNAUTHORIZED=0`（高危），`--no-sandbox`（中危）；只看结构化 args/env，近零误报
- `sp-exfil-instruction`（高危）——system prompt 指令式外发敏感上下文（把对话/用户输入/系统提示词/剪贴板/密钥发送、上传、上报到外部），中文为主 + 英文核心形状；命中所在整句含拒绝/禁止/防范类字样一律放过（M0 误报教训的句级守卫），同句多形状只出一条

### 重构

- sp-secret-embed 抽出强密钥形状表 `matchStrongSecretShape` 供 `mcp-env-credential` 复用（单一事实源，告警文案不变）

### 验收

- 测试 82 → 99（+17：三规则正反用例 + 注册断言）
- dogfood 三靶零误报：本仓 0 / bounty-guard 0 / InjectArena 11 条全为原有规则预期告警（新规则 0 条）
- 端到端正检：投毒 mcp.json fixture（真 key + `--dangerously-skip-permissions` + TLS 关闭）3 条高危全命中，`${GITHUB_TOKEN}` 引用正确放行
- M1 收官：种子规则 10 条（目标 8–10），遗留清单销号 #6

## 0.1.0（2026-09-06）

AI 层安全审计的首个公开版本：形态 A（AI 资产扫描）完整落地，形态 B（回归门禁）引擎就绪并实弹验收。

### 扫描（形态 A）

- 7 条确定性规则：`td-injection-phrase`（指令话术，含写入形状/自我授权/隐藏编码载荷）、`td-hidden-unicode`（零宽/双向/软连字符 + 同形字混排）、`td-exfil-pair`（读写配对）、`sp-secret-embed`（凭据内嵌，按资产类型收窄）、`sp-override-weak`（无条件服从授权）、`mcp-shadow`（同名工具遮蔽）、`mcp-drift`（工具描述指纹基线）
- 资产形状识别：mcpServers / 工具定义（含 `tools[].result` 工具返回值）/ systemPrompt / RAG 文档 / AGENTS.md / CLAUDE.md / 常见命名提示词 txt；攻击语料与普通对象不入资产面
- diff 驱动：PR 上下文走 API diff、本地走 git status，只报新增行（CI 与本地同一判定）
- 输出面净化（SEC-001）：Markdown 表格 / 工作流命令 / 日志三渲染面收口

### 回归门禁（形态 B）

- `regression` 命令：diff→攻击面映射选语料子集，成本闸（试考小样 + 条数上限 50 + 令牌桶限流），接入 `injectarena-judge` 确定性判定（绝不用 LLM 当裁判）
- 基线：治理规则 3 格式，只升不降（降低需 `--allow-lower`）
- 已在 InjectArena 真实 PR 上实弹验收（粘性评论 + 门禁红灯 + BYOK 优雅跳过）

### 工作流原生

- `scan` / `export-corpus` / `pr-comment` / `regression` / `list-rules` 五命令
- GitHub Action（复合 Action，粘性评论 + 标注 + 降级门禁）
- 互守闭环双扫描腿实证：守 InjectArena（红灯演示）+ 守 bounty-guard（mcp-manifest 首扫绿灯）

### 安全

- SEC-001 自查 11 项：7 修 2 记录 2 通过（symlink 环 / 注入双面 / fsmonitor 硬化 / 大小上限 / 退避封顶），详见 `docs/reports/SEC-001-self-audit.md`
- 两轮优化：PR API diff 源、多路径聚合、多块提取、标注硬化、自家 CI、多块行号、同形字、报告封顶

### 判定与语料资产层（同日发布）

- [`injectarena-judge`](https://github.com/Croesus-K/injectarena-judge)：judge + defenseEvaluator + retriever（UMD 纯逻辑，钉 commit 依赖）
- [`prompt-corpus-zh`](https://www.npmjs.com/package/prompt-corpus-zh)：116 条中文提示注入语料 / 5 攻击面（npm 已发布，HF 待同步）

### npm 上架（2026-09-08 增补）

- `prompt-audit@0.1.0` 发布至 [npmjs](https://www.npmjs.com/package/prompt-audit)——`npx prompt-audit scan --git` 即用；shasum `fca5261` 与预检构建一致
- bin 入口补 shebang（`7f459bd`）：无它则 npx 在 macOS/Linux 无法直跑
- 发布验证：`npm view` 0.1.0 / latest；npx 全新安装冒烟（`list-rules` 7 规则、`scan` 检出高危凭据内嵌）
- git tag `v0.1.0` 已推送；发布历程（token 失效 → web 登录安全密钥 → publish EOTP 2FA）见档案 `项目优化历程/prompt-audit/v0.1.0.md`

### 非目标（不变）

不做全量源码扫描；不做运行时 LLM 防火墙；判定层永不引入 LLM。
