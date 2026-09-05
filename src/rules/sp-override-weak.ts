import type { Asset, Finding, Rule } from "../types.js";

/**
 * sp-override-weak —— system prompt 里「易被覆盖的高危授权话术」。
 * 候选规则（PLAN 中标注 M0 dogfood 看误报再定去留）：只命中「无条件服从」
 * 形状的授权语句（无论…都要/必须执行、绝不拒绝、跳过所有限制），
 * 不命中防御方向的同形语句（无论…都必须拒绝/不得透露）——
 * InjectArena 守阵者提示词大量使用后者，正是本规则的主要误报源。
 */
export const spOverrideWeak: Rule = {
  id: "sp-override-weak",
  severity: "medium",
  description:
    "system prompt 中出现「无论用户要求什么都执行」「绝不拒绝」「跳过所有限制」类无条件服从授权——这是攻击者最先利用的话术接口。",
  appliesTo: ["system-prompt"],
  check(asset: Asset): Finding[] {
    const text = asset.text ?? "";
    if (!text) return [];
    const findings: Finding[] = [];
    for (const p of OVERRIDE_PATTERNS) {
      const m = text.match(p.re);
      if (m) {
        findings.push({
          ruleId: "sp-override-weak",
          severity: "medium",
          file: asset.file,
          line: asset.line,
          keyPath: asset.keyPath,
          assetKind: asset.kind,
          message: p.label,
          evidence: clipAround(text, m[0]),
        });
      }
    }
    return findings;
  },
};

const OVERRIDE_PATTERNS: { re: RegExp; label: string }[] = [
  {
    // 「无论…要求/请求/指示…都要|必须|也得 + 执行类动词」，拒绝类动词不算
    re: /无论[^。\n]{0,16}(要求|请求|指示|命令)[^。\n]{0,10}(都要|必须|都得)(?!拒绝|不得|不能)/,
    label: "无条件服从授权：无论…要求…都要/必须…",
  },
  { re: /绝不拒绝|不得拒绝(任何|用户)/, label: "「绝不拒绝」式全量服从授权" },
  { re: /跳过(所有|任何)(限制|检查|审批|确认)/, label: "「跳过所有限制」式授权" },
  { re: /无条件(执行|服从|遵守)/, label: "「无条件执行」式授权" },
];

function clipAround(text: string, matched: string): string {
  const at = text.indexOf(matched);
  const start = Math.max(0, at - 15);
  const end = Math.min(text.length, at + matched.length + 25);
  return text.slice(start, end).replace(/\r?\n/g, "⏎").slice(0, 100);
}
