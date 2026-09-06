# SEC-001 · 安全自查报告（prompt-audit / injectarena-judge / prompt-corpus-zh / InjectArena PR）

> 时间：2026-09-06 · 触发：项目自查要求。扫描对象是**不受信仓库**，攻击面在「文件解析 → 告警 → 渲染输出」与「git 子进程」两条链上。
> 修复原则沿用项目基因：判定层不信任任何文本输入；输出按渲染面收口；宁可漏报不可误报。

## 一、攻击面走查与发现

| # | 位置 | 发现 | 严重度 | 状态 |
|---|---|---|---|---|
| F1 | `scanner.walk` | **符号链接环**：`statSync` 跟随符号链接，恶意仓库里 `ln -s . loop` 会让目录递归失控（DoS） | 高 | ✅ 已修 |
| F2 | `github.toAnnotations` | **工作流命令注入**：`file`/`message` 来自仓库内容，含 `\n` 即可伪造第二条 `::error` 标注（诱导维护者） | 高 | ✅ 已修 |
| F3 | `renderPrComment` / `report.md` | **Markdown/HTML 注入**：告警 message/evidence 含 `</details>`、`|`、`<img>` 可打破折叠块与表格、嵌跟踪图床、伪造维护者通知 | 中 | ✅ 已修 |
| F4 | InjectArena `/api/leaderboard?format=export` | **无限流的公开重接口**：单次可达 500 行 payload 明文，可被脚本刷取（带宽 + SQLite） | 中 | ✅ 已修（PR #1 已更新） |
| F5 | `scanner.walk` / `scan` | **无文件大小上限**：GB 级 .json 全量读入内存 | 中 | ✅ 已修（2MB 上限） |
| F6 | `gitscan.git` | **在被扫仓库里裸跑 git**：`core.fsmonitor` 等配置指向攻击者预置的可执行命令 | 中 | ✅ 已修（`-c core.fsmonitor=false` + `hooksPath=/dev/null`） |
| F7 | `llm.createOpenAICompatible` | 恶意端点给超大 `Retry-After` 可把门禁挂死 | 低 | ✅ 已修（封顶 10s） |
| F8 | 全部规则正则 | ReDoS 面：量词均有界（`{0,8}`/`{0,24}`），无嵌套回溯 | 信息 | ✅ 冒烟测试兜底（10 万级对抗输入） |
| F9 | `upsertStickyComment` | 攻击者可在自己评论里预置 `<!-- prompt-audit-report -->` 骗更新 | 低 | ⚠️ 记录不修：后果只是更新攻击者评论（自身内容不变），门禁不受影响 |
| F10 | `extractFromJson` | 坏 JSON 静默跳过（吞掉 RangeError 等所有异常） | 信息 | ⚠️ 记录不修：扫描器对坏文件应静默降级；无 info 级日志需求前保持简单 |
| F11 | 密钥面 | 三个仓库与 InjectArena 分支内容 grep 无真实凭据（仅规则正则与测试桩） | 信息 | ✅ 通过 |

## 二、修复内容

**prompt-audit（本轮提交）**

- `src/sanitize.ts`（新增）：`stripControlChars` / `mdCell` / `logLine` 三个渲染面收口函数——控制字符折叠、表格分隔符与尖括号转义、超长截断。
- `scanner.ts`：`readdirSync({ withFileTypes })` + 符号链接一律跳过 + 单文件 2MB 上限（目录与单文件两条路径都生效）。
- `github.ts`：标注的 `file`/`message` 过 `logLine`——换行折叠后，注入的 `::` 序列沦为消息文本，不再构成行首命令。
- `pr-comment.ts` / `report.ts`：评论与报告表格的 `file`/`message`/`evidence` 过 `mdCell`——`</details>`、`|`、`<script>` 类载荷失效。
- `gitscan.ts`：git 子进程统一加 `-c core.fsmonitor=false -c core.hooksPath=/dev/null`（array 形式 execFileSync，无 shell 注入面）。
- `llm.ts`：`Retry-After` 退避封顶 10 秒。
- 测试 +8（62 → 70）：注入面三类、symlink 环、大小上限、ReDoS 冒烟。

**InjectArena（PR #1 分支追加提交 `736f1e5`）**

- 导出端点独立令牌桶（5 次/分钟/IP）：429 附 `retry-after`，超限响应不带 payload 数据，落审计日志；默认榜单不受影响。测试 100/100。

## 三、复核过的非发现面（排除记录）

- `execFileSync` 全部为 array 形式——无 shell 拼接注入；`--` 分隔防路径被当选项。
- `repoApiUrl`：`parseRepoSlug` 字符集校验 + `encodeURIComponent` + 固定基底 URL——host 结构性不可变（bounty-guard 同源设计）。
- 基线/指纹（mcp-drift、regression 基线）只写显式传入路径；`--out` 由调用方自担（与一切 CLI 同）。
- `stableStringify` 只读自有键，无原型污染风险；`SECRET_FLAG_RE` 全局正则仅用于 `.replace`，无 lastIndex 状态泄漏。
- 判定链契约：`evaluateDefense` 强制显式注入 judge；脚本 LLM 仅在 `--provider script` 下使用，不存在「LLM 当裁判」面。

## 四、遗留与建议

1. 依赖链无第三方运行时依赖（零依赖），无 supply-chain 面；dev 依赖（vitest/tsx/typescript）更新走常规 renovate 节奏即可。
2. F9 若未来要收口：粘性评论锚点换成「更新自己创建的那条」（记录 comment id）而非文本标记匹配。
3. 互守闭环待落地：本仓库自己的 CI 可挂 bounty-guard 门禁（PLAN 已列），与本报告构成双工具互扫。
4. InjectArena 远端 main 已前进（`37aedfd`），PR #1 合并时若 `src/server.js` 冲突，以「默认视图不变 + 限流加在 export 分支内」为准。
