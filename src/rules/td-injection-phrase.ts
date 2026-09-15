import type { Asset, AssetKind, Finding, Rule } from "../types.js";

/**
 * td-injection-phrase —— 工具描述 / 检索内容里的指令式话术。
 * 短语库取自 InjectArena corpus 的真实 payload 句式（zh + en），
 * 只作用于会被模型当作指令读的文本（工具描述、RAG 文档）。
 *
 * 同一短语在不同资产类型上风险表现不同——工具描述可让 agent 背主，
 * RAG 文档可让回答被毒化。两类 hint 同源但侧重不同：
 * - 默认 hint 偏工具描述语境（更常见的入口）
 * - hints["retrieved-content"] 偏内容投毒语境（专门覆盖 RAG 文档场景）
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
          finding(asset, p.label, m[0], pickHint(p, asset.kind)),
        );
      }
    }
    return findings;
  },
};

interface Phrase {
  label: string;
  re: RegExp;
  /** 默认 hint——适用于 tool-description / mcp-config / system-prompt 等 */
  hint: string;
  /** 资产类型专属 hint——优先于默认 hint；按资产场景定制提示读者风险侧重 */
  hints?: Partial<Record<AssetKind, string>>;
}

/** 选用 hint：kind 有专属时取专属，否则回退默认。 */
function pickHint(p: Phrase, kind: AssetKind): string {
  return p.hints?.[kind] ?? p.hint;
}

const PHRASES: Phrase[] = [
  {
    label: "指令覆盖",
    re: /忽略.{0,8}(之前|此前|先前|以上|原有)(的)?(所有|全部)?(指令|提示|设定|规则)/,
    hint: "「忽略之前的指令」是提示注入的标志性开场白",
    hints: {
      "retrieved-content": "「忽略之前的指令」类开场白出现在 RAG 文档中——这是内容投毒的标志性手法，模型读到的外部素材在试图覆盖既有指令",
    },
  },
  {
    label: "指令覆盖（en）",
    re: /ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)/i,
    hint: "英文指令覆盖句式（ignore previous instructions 等）",
    hints: {
      "retrieved-content": "英文指令覆盖句式出现在 RAG 文档中——内容投毒的常见载体",
    },
  },
  {
    label: "套取系统提示词",
    re: /(系统提示|初始设定|system\s*prompt)[^。\n]{0,24}(输出|复述|打印|发送|外发|泄露|告知|提供|写入|写进|带回|附上)/i,
    hint: "要求把系统提示词送出去或写进回复/参数——正常的工具描述与返回值不应谈论系统提示词",
    hints: {
      "retrieved-content": "RAG 文档要求把系统提示词外发——正常的检索内容不应关心系统提示词，模型把外部素材当指令读是典型投毒链",
    },
  },
  {
    label: "伪称系统指令",
    re: /((优先|凌驾)于)一切[^。\n]{0,6}指令|(最高优先级[，,]?\s*覆盖)|(\boverride[s]?\s+all\s+(human\s+)?instructions\b)/i,
    hint: "「优先于一切人工指令」类自我授权——试图凌驾人工闸门的话术",
    hints: {
      "retrieved-content": "RAG 文档中出现「优先于一切人工指令」——内容试图凌驾人工闸门",
    },
  },
  {
    label: "对用户保密",
    re: /(不要|不得|别)(向)?(用户|任何人)(告诉|告知|透露|泄露|提及)|(do\s*not|never)\s+(tell|reveal|inform|disclose)/i,
    hint: "「不要告诉用户」类话术让工具背着他干活",
    hints: {
      "retrieved-content": "RAG 文档中要求对用户隐瞒——内容操纵的常见手法，让模型在回答时绕过对用户的透明性",
    },
  },
  {
    label: "绕过人工审批",
    re: /无需(请示|审批|确认|授权)|(未经|不必|不用)(请示|审批|授权)|(跳过|绕过|无视)(审批|所有限制|安全检查|人工确认)/,
    hint: "「无需请示/直接执行」试图拆掉人工闸门——高危动作审批链上的红旗",
    hints: {
      "retrieved-content": "RAG 文档中要求绕过审批——内容操纵的红旗，外部素材试图拆掉人工闸门",
    },
  },
  {
    label: "伪造权威",
    re: /自称(上级|运维|管理员|审计|官方|系统)|(pretend|claim)\s+to\s+be\s+(the\s+)?(admin|operator|developer|official|system)/i,
    hint: "伪造身份是典型越狱前置话术",
    hints: {
      "retrieved-content": "RAG 文档中出现伪造权威身份——内容操纵前置话术，让模型降级防御",
    },
  },
  {
    label: "隐藏编码载荷",
    re: /[A-Za-z0-9+/]{60,}={0,2}/,
    hint: "长 base64 串——编码是指令隐藏的经典手法（L3 变形绕过的载体），工具描述里几乎不可能是正常内容",
    hints: {
      "retrieved-content": "长 base64 串出现在 RAG 文档中——base64 在文档里合法但配合指令语境极可能是编码载荷（投毒典型手法）",
    },
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
