import type { Asset, Finding, Rule } from "../types.js";

/**
 * td-hidden-unicode —— 提示词/工具描述里的隐藏字符。
 * 零宽字符、双向控制符、软连字符对人是不可见的，但会进入模型上下文——
 * 既可夹带指令，也可让两段"看起来一样"的文本骗过字符串比较。
 */
export const tdHiddenUnicode: Rule = {
  id: "td-hidden-unicode",
  severity: "high",
  description:
    "AI 资产文本中出现零宽字符 / 双向控制符 / 软连字符——肉眼不可见但会进入模型上下文，可夹带指令或混淆比对。",
  appliesTo: ["tool-description", "system-prompt", "retrieved-content", "mcp-config"],
  check(asset: Asset): Finding[] {
    const text = asset.text ?? stringify(asset.obj);
    if (!text) return [];
    const findings: Finding[] = [];
    const seen = new Map<number, number>();
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      if (cp !== undefined && isHiddenCodePoint(cp)) {
        seen.set(cp, (seen.get(cp) ?? 0) + 1);
      }
    }
    for (const [cp, count] of seen) {
      findings.push({
        ruleId: "td-hidden-unicode",
        severity: "high",
        file: asset.file,
        line: asset.line,
        keyPath: asset.keyPath,
        assetKind: asset.kind,
        message: `隐藏字符：U+${cp.toString(16).toUpperCase().padStart(4, "0")}（${describe(cp)}）出现 ${count} 次`,
        evidence: showAround(text, cp),
      });
    }
    return findings;
  },
};

const HIDDEN: ReadonlyMap<number, string> = new Map([
  [0x200b, "零宽空格"],
  [0x200c, "零宽非连接符"],
  [0x200d, "零宽连接符"],
  [0x2060, "字词连接符"],
  [0xfeff, "零宽不换行空格（BOM）"],
  [0x00ad, "软连字符"],
  [0x202a, "双向嵌入（LRE）"],
  [0x202b, "双向嵌入（RLE）"],
  [0x202c, "双向格式终止（PDF）"],
  [0x202d, "双向覆盖（LRO）"],
  [0x202e, "双向覆盖（RLO）"],
  [0x2066, "双向隔离（LRI）"],
  [0x2067, "双向隔离（RLI）"],
  [0x2068, "双向首段隔离（FSI）"],
  [0x2069, "双向隔离终止（PDI）"],
]);

function isHiddenCodePoint(cp: number): boolean {
  return HIDDEN.has(cp);
}

function describe(cp: number): string {
  return HIDDEN.get(cp) ?? "隐藏字符";
}

function showAround(text: string, cp: number): string {
  const idx = text.indexOf(String.fromCodePoint(cp));
  const start = Math.max(0, idx - 20);
  const end = Math.min(text.length, idx + 40);
  const around = text
    .slice(start, end)
    .replace(/\r?\n/g, "⏎")
    .replace(/[\u200b-\u200f\u2060\u2066-\u2069\ufeff\u00ad]/g, (ch) =>
      `⟨U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}⟩`);
  return `${around}（⟨⟩ 内为不可见字符的码点）`.slice(0, 120);
}

function stringify(obj: unknown): string {
  if (obj === undefined) return "";
  try {
    return JSON.stringify(obj) ?? "";
  } catch {
    return "";
  }
}
