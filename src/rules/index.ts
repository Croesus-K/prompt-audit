import type { Finding, Rule, ScanResult } from "../types.js";
import { tdInjectionPhrase } from "./td-injection-phrase.js";
import { tdHiddenUnicode } from "./td-hidden-unicode.js";
import { tdExfilPair } from "./td-exfil-pair.js";
import { spSecretEmbed } from "./sp-secret-embed.js";
import { spOverrideWeak } from "./sp-override-weak.js";

/** M0 种子规则集（6 条；mcp-drift 需基线设施，M1 再上） */
export const RULES: Rule[] = [
  tdInjectionPhrase,
  tdHiddenUnicode,
  tdExfilPair,
  spSecretEmbed,
  spOverrideWeak,
];

/**
 * mcp-shadow —— 跨 server 同名工具遮蔽。这是跨资产规则（单条资产判不出），
 * 在 scanner 收集完所有工具定义后统一跑。
 */
export function checkMcpShadow(findings: Finding[], result: ScanResult): void {
  const tools = result.assets.filter((a) => a.kind === "tool-description");
  const byName = new Map<string, typeof tools>();
  for (const t of tools) {
    const name = (t.extra?.tool as string | undefined) ?? t.keyPath.split(".").pop() ?? "";
    const list = byName.get(name) ?? [];
    list.push(t);
    byName.set(name, list);
  }
  for (const [name, list] of byName) {
    if (list.length < 2) continue;
    const servers = [...new Set(list.map((t) => t.file))].join("、");
    findings.push({
      ruleId: "mcp-shadow",
      severity: "medium",
      file: list[1].file,
      line: list[1].line,
      keyPath: list[1].keyPath,
      assetKind: "tool-description",
      message: `同名工具「${name}」出现在 ${servers} 等多处——后加载的可能遮蔽先加载的`,
      evidence: `${name}: ${list.map((t) => `${t.file}:${t.line}`).join(", ")}`,
    });
  }
}

/** 按严重度降序、文件行号升序排列 */
export function sortFindings(findings: Finding[]): Finding[] {
  const order = { high: 0, medium: 1, low: 2, info: 3 } as const;
  return [...findings].sort(
    (a, b) =>
      order[a.severity] - order[b.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );
}
