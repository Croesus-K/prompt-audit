import { COMMENT_MARKER } from "./github.js";
import { mdCell } from "./sanitize.js";
import type { Finding, ScanResult, Severity } from "./types.js";

/** 门禁：存在严重度 ≥ 阈值的告警即红灯 */
const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3 };

export function gateExit(findings: Finding[], failOn: Severity): 0 | 1 {
  const threshold = SEVERITY_RANK[failOn];
  return findings.some((f) => SEVERITY_RANK[f.severity] >= threshold) ? 1 : 0;
}

const ICONS: Record<Severity, string> = {
  high: "🔴",
  medium: "🟠",
  low: "🟡",
  info: "🔵",
};

const PR_COMMENT_CAP = 20;

/** PR 粘性评论正文（带标记锚点，供下次扫描更新而非新建） */
export function renderPrComment(results: ScanResult[], opts: { version?: string; failOn?: Severity } = {}): string {
  const findings = results.flatMap((r) => r.findings);
  const count = (sev: Severity) => findings.filter((f) => f.severity === sev).length;
  const lines: string[] = [];

  lines.push(COMMENT_MARKER);
  lines.push("## 🛡️ prompt-audit · AI 资产扫描");
  lines.push("");
  if (findings.length === 0) {
    lines.push("✅ **AI 资产干净**——本次变更中的 system prompt / 工具描述 / MCP 配置没有触发任何注入或凭据规则。");
  } else {
    lines.push(
      `发现 **${findings.length}** 条告警：🔴 高危 ${count("high")} · 🟠 中危 ${count("medium")} · 🟡 低危 ${count("low")}`,
    );
  }
  const changed = results.flatMap((r) => r.git?.changedFiles ?? []);
  if (changed.length > 0) {
    lines.push("");
    lines.push(`<details><summary>本次 diff 审查范围（${changed.length} 个文件，只报新增行）</summary>`);
    lines.push("");
    lines.push(changed.map((f) => `\`${mdCell(f, 120)}\``).join(" · "));
    lines.push("");
    lines.push("</details>");
  }
  if (findings.length > 0) {
    lines.push("");
    lines.push("| 严重度 | 位置 | 规则 | 说明 |");
    lines.push("|---|---|---|---|");
    for (const f of findings.slice(0, PR_COMMENT_CAP)) {
      lines.push(
        `| ${ICONS[f.severity]} ${f.severity} | \`${mdCell(f.file, 120)}:${f.line}\` | \`${f.ruleId}\` | ${mdCell(f.message)} |`,
      );
    }
    if (findings.length > PR_COMMENT_CAP) {
      lines.push(`| | | | …另有 ${findings.length - PR_COMMENT_CAP} 条，完整列表见 CI 日志 |`);
    }
  }
  lines.push("");
  lines.push(
    `> 门禁 \`--fail-on ${opts.failOn ?? "high"}\` · 判定为确定性规则，绝不用 LLM 当裁判 · ${opts.version ?? "prompt-audit"}${results.some((r) => r.ignoredRules.length) ? ` · 忽略规则：${[...new Set(results.flatMap((r) => r.ignoredRules))].join(", ")}` : ""}`,
  );
  return lines.join("\n");
}

