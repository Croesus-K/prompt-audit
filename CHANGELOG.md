# Changelog

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
