# 路线图（ROADMAP）

prompt-audit 的开发节奏按 `v0.x.y` 递增，每轮都对应可立刻 dogfood 的可运行状态。
本文件列出已规划未发布的特性、每条的「现在不做会怎样」与预计落点版本。

---

## v0.3.0（当前轮，已实现，待发版）

两条新规则 + allow 内容级精确豁免。

| # | 项 | 描述 | 现在不做会怎样 |
|---|---|---|---|
| C1 | `td-missing-schema` | 工具定义缺 `parameters`/`inputSchema` | 模型拿到无形状工具 → 可被诱导用任意参数调用 |
| C1 | `td-tool-binding` | 工具描述硬编码「调用其他工具」或绑死参数 | 模型读到即被编排跨工具链路，注入面乘积放大 |
| C2 | `allow.content` | allow 段附加 regex 字段做内容级精确豁免 | 同路径上多条发现要么全豁免要么全告警，无法精细 |

见 `CHANGELOG.md#0.3.0`。

---

## v0.4.0（下一轮规划）

### B1 — 把 injectarena-judge 发到 npm

现在 `injectarena-judge` 仅以本地脚本形式存在（InjectArena 仓库内 `judge/` 目录）。
发包后的好处：
- 第三方 CTF/红队练习场可 `npm i -g injectarena-judge` 直接复用同一套判定模型
- 版本绑定与 prompt-audit 对齐（都用 `@latest` 或同步升 minor）

阻塞：需要 npm 账号 webauthn OTP（用户尚未提供）。

### A1 — M3 真实流量补完

把 prompt-audit 接入到真实 CI 跑一轮：
- 在更多真实仓库（每个 dev agent、每个 MCP 客户端）上跑 prompt-audit
- 收集 0.3.0 漏报/误报样本，作为 v0.4.0 规则迭代依据

阻塞：缺 API key（用户尚未提供 `INJECTARENA_API_KEY` 等）。

### A2 — M4 语料反馈闭环

把每次扫描结果（含 allow 命中、豁免、ignore）回传到一处语料库；
以语料反推「哪些告警模式稳定是误报」「哪些豁免被反复使用」。

阻塞：同 A1，需要外发 API。

---

## v0.5.0（之后）

### 规则迭代

- **结构化规则覆盖率**：`td-*` 系列从 10 条扩到 14-16 条
  - `td-result-trust`（高危）—— 工具返回值未声明「不可信」语义就直接进上下文
  - `td-schema-overbroad`（中危）—— `parameters` schema 过宽（`additionalProperties: true` + 无 required）
  - `td-prompt-in-result`（高危）—— 工具返回值含 prompt-injection 模式（与 `sp-*` 复用判定）
- **多语言支持**：现有 zh/en 双语；加入 ja/ko 模式（来自 MCP 社区贡献）

### 命令行增强

- `--format json` 输出：给 CI 与第三方审计工具消费
- `--severity <lvl>` 临时降级门禁（`--fail-on` 之上再叠一层）
- `prompt-audit explain <rule-id>`：展开规则的命中原因、误报边界、绕过示例

### Web Dashboard（E2）

最小版 `prompt-audit serve <root>` 子命令：
- 起一个本地 HTTP 服务（默认 127.0.0.1:7481），渲染扫描发现的资产/告警/豁免
- 静态 HTML + 内联 CSS，零依赖；只为单用户 dogfood 设计（无认证）
- 入口：`/index.html` 资产盘点、`/findings.html` 告警过滤、`/allow.html` 豁免配置编辑

### pre-commit hook（E1）

`prompt-audit init-hooks` 子命令：
- 在仓库 `.git/hooks/pre-commit` 安装轻量 hook（仅修改被提交文件，不全仓库扫描）
- hook 走 `prompt-audit scan <changed-files>` 增量模式
- 任何 high/medium 命中 → exit 1 阻止提交

---

## 长期（v1.0.0 之前）

### 可信包 + 签名

- npm publish 走 sigstore/cosign 签名
- 提供 `prompt-audit verify <pkg>` 子命令校验工具链自身的来源

### 规则包热加载

- 允许用户在自己的 npm 包里发布 rule pack
- `prompt-audit --rules ./my-rules/` 或 `package.json#promptAudit.rules`
- 规则格式仍是 `{ id, severity, description, appliesTo, check }`，外部包只要满足形状即可注册

### 跨工具横评

- 与 semgrep / snyk / Bearer 等 SAST 工具对比 AI 层规则的覆盖差距
- 输出「prompt-audit-only」清单，证明 AI 层资产是这些工具的盲区

---

## 不做（明确放弃）

- **LLM 集成做判定**：prompt-audit 是静态规则工具，不调用任何 LLM；
  引入 LLM 会让单次扫描延迟从 ms 级跳到 s 级且不可重现，与 CI 门禁场景相悖。
- **在线资产抓取**：仅扫仓库内文件，不联网读 README/官网/文档站等。
- **自动修复**：只告警，不写 PR 自动改用户提示词——提示词是产品决策，不是漏洞。

---

最后更新：与 v0.3.0 同步发布。