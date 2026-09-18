# Changelog

## 0.3.0（2026-09-19）

两条新规则覆盖 v0.2.0 留下的两个攻击面盲区，allow 段升级为「内容级精确豁免」，新增两个开发者友好子命令。

### 新增规则（2 条）

- `td-missing-schema`（中危）——工具定义缺少 `parameters`/`inputSchema`。结构性检查：`obj.parameters` 与 `obj.inputSchema` 同时缺失 → 告警。MCP/A2A 生态普遍要求工具带 schema 才能安全调用；缺 schema 的工具一旦暴露给模型，攻击者可诱导模型用任意参数调用，等价于给了模型一个无形状的 API 入口
- `td-tool-binding`（高危）——工具描述硬编码「调用其他工具」或绑死参数内容。4 条正则覆盖 zh/en：用户意图→工具调用、串调其他工具、硬编码强制串调、绑死工具参数内容。典型泄露：「你必须先用 search_tool 检索 X、再用本工具提交」、「把上一轮的输出原样作为参数」。模型读到这些描述即被编排跨工具链路，注入点面乘积放大

### allow 段升级：内容级精确豁免

- `allow[i].content?: { regex: string, assetKind?: AssetKind, keyPathPrefix?: string }`
- 在 path+rules 命中之后，再对**finding evidence**（命中片段+少量上下文）做正则匹配 + 范围过滤
- 关键语义：按 evidence 而非 asset.text 匹配——同一资产上多条发现只豁免 evidence 命中的那一条，保留同文件同规则的其它告警
- 加载期校验 regex（避免扫描期才抛错）；assetKind 限定为已知 AssetKind；keyPathPrefix 限定 keyPath 前缀
- 典型用例：关卡 `levels/**` 上放行「演练 `FLAG{OPEN-9921}`」的真演练字段，但保留同路径真密钥形态告警

### 新增子命令（2 个）

- `prompt-audit init-hooks [--target <dir>] [--fail-on <sev>] [--force]`
  - 在 `<target>/.git/hooks/pre-commit` 装轻量门禁
  - hook 内容：取 staged 文件 → 跑 `prompt-audit scan <staged> --fail-on <sev>` → exit 1 即阻提交
  - 既有 hook 存在时拒绝覆盖（除非 `--force`）；chmod 0o755
  - 无认证 / 无远端调用：纯本地 dogfood 工具
- `prompt-audit serve [path] [--host <addr>] [--port <n>]`
  - 起本地 Web 仪表盘（默认 `127.0.0.1:7481`）
  - 路由：`/`（HTML 总览）、`/scan.json`、`/findings.json`、`/assets.json`、`/allow.json`
  - 零依赖（Node 内置 http + 内联 HTML 模板）
  - 单用户 dogfood 设计：默认绑 loopback、不写盘、不联网

### 配置语义

- `--ignore <ruleId>` 仍是规则级全仓库关停；allow 现在可做到「内容级单点豁免」
- content 段缺省 → 维持 v0.2.0 行为（仅按 path×ruleId 豁免）
- content 段存在但 asset/evidence 不可得 → 保守失败（不豁免）

### 验收

- 测试 135 → 172（+37：td-missing-schema 5 + td-tool-binding 6 + content 段加载/校验/匹配 7 + scanner 端到端 1 + isAllowed 单元 3 + init-hooks 单元 6 + hook 端到端 2 + serve 仪表盘 7）
- dogfood 双靶：InjectArena 5 条关卡预期告警照常 / 0 误报回归；用演练 flag 正则替换原 allow 后仍豁免 6 条 / 5 条；serve 仪表盘 200 OK + findings.json 正确反映 5 条 td-* 告警
- TypeScript：`tsc --noEmit` 干净通过

## 0.2.0（2026-09-16）

M0 遗留收官：豁免机制（#3）。引入路径级 allow 段，替代「全规则关停」的粗变通——「这条规则在这条路径上放过」与 `--ignore <ruleId>` 全仓库关停正交。

### 新增特性

- `.prompt-audit.json` 仓库根配置文件（`allow` 段）：`[{ path: string, rules?: string[] }]`——命中 `path` glob 的资产，在 `rules` 列出的规则上免于告警（`rules` 缺省即该路径下放行全部规则）
- 零依赖 glob 引擎（`src/glob.ts`）：`**` / `*` / `?` 三种通配，锚定路径段，移植自 bounty-guard 已实战验证实现
- 报告渲染新增「豁免配置」行：`豁免配置：<path>`（命中豁免 N 条）——零命中或不配置时显式「无」，不静默
- `--ignore <ruleId>` 行为不变：仍为规则级全仓库关停，与 allow 段正交叠加

### 配置语义

- allow 是**白名单**（命中则免），不是黑名单（命中则告警）；与 `--ignore` 维度互补而非重复
- `path` 走仓库相对路径，正斜杠分隔；隐式锚定仓库根（`levels/**` 匹配 `levels/L1.json`、不匹配 `tools/levels/x.json`）
- `rules` 为 rule id 字符串数组；缺省即「放行全部规则」；id 不存在时配置校验失败（loud-fail，仿 `.bountyrc.json`）

### InjectArena 迁移

- 移除 `ignore: 'sp-secret-embed'`（粗变通，单规则全仓库关停）
- 新增 `.prompt-audit.json`：`{ allow: [{ path: "levels/**", rules: ["sp-secret-embed"] }] }`——关卡机制下密令内嵌是预期告警，非误报
- 其余规则（td-injection-phrase / td-exfil-pair 等）继续按设计门禁关停：L4/L5/L6 关卡存在这些模式是教学样本，应有红灯

### 验收

- 测试 117 → 135（+18：glob 引擎 11 + allowlist 加载 7 + scanner 端到端 6，正反用例 + 边缘 glob + 与 `--ignore` 正交）
- dogfood 双靶：InjectArena 6 条 sp-secret-embed 全豁免 / 5 条关卡预期告警照常 / bounty-guard 0 告警零回归
- TypeScript：`tsc --noEmit` 干净通过
- M0 遗留清单销号 #3

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
