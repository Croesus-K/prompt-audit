# M0 扫描报告 · 01 — bounty-guard（MCP 接入配置）

> prompt-audit M0 dogfood 第一份报告。扫描对象：bounty-guard 仓库（`c484251`，2026-09-04）README 中的 `mcpServers` 接入配置——PLAN 规则 1（工具描述指令话术）的演示场景。
>
> 扫描器：prompt-audit 0.0.1 M0 原型（TypeScript，零运行时依赖；规则 6 条，测试 30 项全绿）
> 扫描时间：2026-09-05 · 复现命令：`npx tsx src/cli.ts scan <bounty-guard 仓库路径>`

## 一、资产盘点

| 类型 | 位置 | 路径 | 摘要 |
|---|---|---|---|
| MCP 配置 | `README.md:86` | `mcpServers` | server `bounty-guard`：`npx -y bounty-guard mcp` |

整个仓库只有这一处 AI 层资产：README 第 86 行的内联 JSON

```json
{ "mcpServers": { "bounty-guard": { "command": "npx", "args": ["-y", "bounty-guard", "mcp"] } } }
```

## 二、告警明细

**0 条。**

## 三、判定与误报率

| 指标 | 数值 |
|---|---|
| 告警 | 0 |
| 人工判定为误报 | 0 |
| **误报率** | **0/0（无告警可判）** |

0 告警是**正确结果**，理由：

1. 该片段只声明启动命令与参数，没有任何工具描述文本——`td-injection-phrase` 没有可检查的话术面。
2. 没有 `env` 字段——`sp-secret-embed` 无凭据可查。
3. 没有第二个 server、没有同名工具——`mcp-shadow` 不适用。
4. 扫描器按「资产形状」提取（`name + description + parameters/inputSchema` 才算工具定义），README 其余内容、package.json 这类「有 name 也有 description」的普通对象都没有被误当资产——**没有为凑告警而扩大资产口径**。

### 近命中分析：为什么 bounty-guard 的真实工具不触发 `td-exfil-pair`

bounty-guard 的 MCP 工具（`scan_git` / `scan_diff` / `list_rules` / `doctor`）中，`scan_diff` 确实是「读 diff 内容」型工具，粘性评论确实是「对外写」动作。但二者**不构成外传配对**：评论的目标固定为当前仓库的 PR，数据不出系统边界。`td-exfil-pair` 的口径是「敏感内容 × 外发通道」（InjectArena L5 的 `send_report` 形状：内容可写往**任意指定收件渠道**），这与 M0 的判定一致，口径澄清记录在案。

### 覆盖边界（如实记录）

- bounty-guard 的工具描述长在 `src/mcp/*.ts` 源码里。prompt-audit 不做源码扫描（继承 PLAN 非目标），因此本次实际发布的工具描述**不在扫描面内**。
- 衔接点：若 bounty-guard 未来在仓库维护一份 AI 资产清单（如 `mcp-manifest.json`，含各工具 description），即可纳入 prompt-audit 扫描——这正是方案「互守闭环」中「bounty-guard 仓库的 MCP 描述 → prompt-audit 静态扫描」一条的落地形态，M1 后可回补验证。

## 四、附带盘点：本机 AGENTS.md / CLAUDE.md

M0 目标之四（真实 AI 资产盘点）。检索范围：Desktop 全部项目、`~/.claude`、`~/.agents`、`~/.zcode`、用户主目录。

**结果：0 个文件。** 本机当前没有全局或项目级 AGENTS.md / CLAUDE.md。盘点本身即结论：extractor 对 AGENTS.md / CLAUDE.md 的支持（全文作为 system-prompt 资产）已就绪并有用例覆盖（`tests/extract.test.ts`），等第一个此类资产出现即可纳入扫描。

## 五、结论

- 靶子 1 通过：资产识别准、0 告警为正确结果、无误报。
- 扫描器在「诚实的目标」上安静——这是宁可漏报不可误报原则的第一份实证。
