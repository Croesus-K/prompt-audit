# prompt-audit

> Prompt 审计官 —— AI 层安全审计与门禁：把 system prompt、MCP 配置、工具描述当代码审（prompt audit / prompt injection scanner / MCP security scanner / 提示注入扫描）。

bounty-guard 守的是人写的代码，InjectArena 测的是 LLM 本身；**prompt-audit** 站在两者中间，审的是 **AI 应用自身**。
系统提示词、agent 配置、MCP 工具描述——在所有传统扫描器眼里是"普通文本"，实际是真正的可执行层：prompt 就是程序，工具描述能操纵 agent。

**为什么叫 prompt-audit**：audit（审计）就是这个工具做的全部动作——形态 A 审 AI 资产里的投毒与危险权限，形态 B 审每次改动后的拦截率回归。`prompt audit` / `security audit` 是安全领域的高频搜索词，两个词常见、好拼、不易打错——模糊搜索友好，不依赖品牌记忆。

## 它管两件事

| 形态 | 干什么 | 引擎来源 |
|---|---|---|
| **A · AI 资产扫描** | 扫 system prompt / `mcp.json` / 工具描述里的投毒话术、隐藏字符与危险权限组合 | bounty-guard 的 diff 管道 + 规则引擎 |
| **B · prompt 回归门禁** | prompt 或工具定义变更的 PR，自动用注入语料回归测试，拦截率低于基线即红灯 | InjectArena 守方评测引擎 + 确定性判定器 |

## 四个差异点

1. **中文语料**——规则短语库与攻击语料以中文为主、中英混合（InjectArena 100 条语料直接复用），提示词安全 / 提示注入检测的中文语料目前几乎空白。
2. **diff 驱动**——只审 AI 资产的新增行；回归门禁只跑与改动段落相关的攻击面语料子集（成本闸，呼应"只审新增行"）。
3. **工作流原生**——CLI / GitHub Action / MCP Server / VS Code，形态与 bounty-guard 同源，粘性评论 + 门禁 + 无 Key 优雅降级。
4. **确定性判定**——绝不用 LLM 当裁判：扫描告警必须挂在真实代码行上；回归判定只看输出中是否出现受控标记（InjectArena 的 judge 契约）。

## 语料飞轮

InjectArena 攻防双榜产生的真实 payload 回流为 prompt-audit 的回归语料；prompt-audit 扫出的真实投毒样本反哺 InjectArena 关卡。
两个项目共用 `corpus/` schema，互相喂数据。

## Roadmap

- [x] **M0 · dogfood**：扫自己的仓库——bounty-guard 的 MCP server 配置、InjectArena 五个守阵者 system prompt（`levels/*.json`），产出第一批真实告警（误报率 38.5% → 修复后 0%，报告见 [docs/reports/](docs/reports/)）
- [ ] **M1 · CLI**：`npx prompt-audit scan --git`，AI 资产规则包（8–10 条种子规则，见 [docs/PLAN.md](docs/PLAN.md)）
- [ ] **M2 · GitHub Action**：粘性评论 + `--fail-on high` 门禁
- [ ] **M3 · 回归门禁**：拦截率基线 JSON + diff 驱动语料子集 + NDJSON 流式进度
- [ ] **M4 · 语料回流**：InjectArena 双榜 payload 自动回流语料库（每周定时）

## License

[MIT](LICENSE)
