import type { Asset, Finding, Rule } from "../types.js";

/**
 * td-injection-phrase —— 工具描述 / 检索内容里的指令式话术。
 * 短语库取自 InjectArena corpus 的真实 payload 句式（zh + en），
 * 只作用于会被模型当作指令读的文本（工具描述、RAG 文档）。
 */
export const tdInjectionPhrase: Rule = {
  id: "td-injection-phrase",
  severity: "high",
  description:
    "工具描述或检索内容里出现指令式话术（忽略指令、复述系统提示词、无需请示、伪造权威、不要告诉用户等）——工具描述能操纵 agent，检索内容可被投毒。",
  appliesTo: ["tool-description", "retrieved-content"],
  check(asset: Asset): Finding[] {
    const text = asset.text ?? "";
    if (!text) return [];
    const findings: Finding[] = [];
    for (const p of PHRASES) {
      const m = text.match(p.re);
      if (m) {
        findings.push(
          finding(asset, p.label, m[0], p.hint),
        );
      }
    }
    return findings;
  },
};

interface Phrase {
  label: string;
  re: RegExp;
  hint: string;
}

const PHRASES: Phrase[] = [
  {
    label: "指令覆盖",
    re: /忽略.{0,8}(之前|此前|先前|以上|原有)(的)?(所有|全部)?(指令|提示|设定|规则)/,
    hint: "「忽略之前的指令」是提示注入的标志性开场白",
  },
  {
    label: "指令覆盖（en）",
    re: /ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)/i,
    hint: "英文指令覆盖句式（ignore previous instructions 等）",
  },
  {
    label: "套取系统提示词",
    re: /(系统提示|初始设定|system\s*prompt)[^。\n]{0,24}(输出|复述|打印|发送|外发|泄露|告知|提供|写入|写进|带回|附上)/i,
    hint: "要求把系统提示词送出去或写进回复/参数——正常的工具描述与返回值不应谈论系统提示词",
  },
  {
    label: "伪称系统指令",
    re: /((优先|凌驾)于)一切[^。\n]{0,6}指令|(最高优先级[，,]?\s*覆盖)|(\boverride[s]?\s+all\s+(human\s+)?instructions\b)/i,
    hint: "「优先于一切人工指令」类自我授权——试图凌驾人工闸门的话术",
  },
  {
    label: "对用户保密",
    re: /(不要|不得|别)(向)?(用户|任何人)(告诉|告知|透露|泄露|提及)|(do\s*not|never)\s+(tell|reveal|inform|disclose)/i,
    hint: "「不要告诉用户」类话术让工具背着他干活",
  },
  {
    label: "绕过人工审批",
    re: /无需(请示|审批|确认|授权)|(未经|不必|不用)(请示|审批|授权)|(跳过|绕过|无视)(审批|所有限制|安全检查|人工确认)/,
    hint: "「无需请示/直接执行」试图拆掉人工闸门——高危动作审批链上的红旗",
  },
  {
    label: "伪造权威",
    re: /自称(上级|运维|管理员|审计|官方|系统)|(pretend|claim)\s+to\s+be\s+(the\s+)?(admin|operator|developer|official|system)/i,
    hint: "伪造身份是典型越狱前置话术",
  },
];

function finding(asset: Asset, label: string, matched: string, hint: string): Finding {
  return {
    ruleId: "td-injection-phrase",
    severity: "high",
    file: asset.file,
    line: asset.line,
    keyPath: asset.keyPath,
    assetKind: asset.kind,
    message: `${label}：${hint}`,
    evidence: clip(matched, asset.text ?? ""),
  };
}

/** 取命中片段并带少量上下文，换行折叠为 ⏎，超长截断。 */
export function clip(matched: string, text: string, width = 60): string {
  const at = text.indexOf(matched);
  const start = Math.max(0, (at < 0 ? 0 : at) - 10);
  const end = Math.min(text.length, start + width);
  return text
    .slice(start, end)
    .replace(/\r?\n/g, "⏎")
    .trim()
    .slice(0, 80);
}
