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
    // 同形字混排（PLAN 定义内）：拉丁单词里混入视觉等价但码点不同的字符——
    // 「sуstem」（西里尔 у）、「systеm」（西里尔 е）、「adm𝐢n」（数学粗体 i）、
    // 「sｙstem」（全角 y）等。肉眼看不出但既骗过字符串比对、也误导人审；
    // 纯同文字文本（整词全西里尔 / 整词全希腊 / 整词全数学符号 / 整词全角）不误伤。
    //
    // 实现刻意走「for...of + 显式码点判断」而非 regex 字符类：V8 的 regex 字符类
    // 在没有 /u 标志时做 Unicode case folding（[A-Z] 通过大小写折叠自动覆盖全角 Ａ-Ｚ），
    // 会导致 ASCII 拉丁被误判为「同形字」，大面积误伤。显式码点比对无此副作用。
    const mixedSeen = new Set<string>();
    for (const run of findLatinRuns(text)) {
      if (!isMixedScript(run) || mixedSeen.has(run)) continue;
      mixedSeen.add(run);
      findings.push({
        ruleId: "td-hidden-unicode",
        severity: "high",
        file: asset.file,
        line: asset.line,
        keyPath: asset.keyPath,
        assetKind: asset.kind,
        message: `同形字混排：「${run.slice(0, 24)}」——ASCII 拉丁与视觉等价字符（同形字）同词混排`,
        evidence: clipMixed(text, run),
      });
    }
    return findings;
  },
};

/**
 * 同形字字符块——视觉与 ASCII 拉丁等价但码点不同：
 * - \u0400-\u04FF 西里尔（含 А/а/Е/е/О/о/Р/р/С/с/Т/т/Х/х 等拉丁形字母）
 * - \u0370-\u03FF 希腊（含 Α/α/Β/β/Ε/ε/Η/η/Ι/ι/Κ/κ/Μ/μ/Ν/ν/Ο/ο/Ρ/ρ/Τ/τ/Χ/χ 等拉丁形字母）
 * - \u1D400-\u1D7FF 数学字母数字符号（含 𝐀-𝐳 数学粗/斜/手写/等宽拉丁形式）
 * - \uFF21-\uFF3A / \uFF41-\uFF5A 全角 ASCII 大写 / 小写字母
 *
 * 数字同形（0/O、1/l/Ⅰ 等）单独看无上下文字时是边缘判定，本规则暂不覆盖——避免误伤正常标识符
 */

/** 单码点是否属于「拉丁 + 同形字」字符类中的任一区块 */
function isLatinOrHomoglyph(cp: number): boolean {
  return (
    (cp >= 0x41 && cp <= 0x5a) ||
    (cp >= 0x61 && cp <= 0x7a) ||
    (cp >= 0x0370 && cp <= 0x03ff) ||
    (cp >= 0x0400 && cp <= 0x04ff) ||
    (cp >= 0x1d400 && cp <= 0x1d7ff) ||
    (cp >= 0xff21 && cp <= 0xff3a) ||
    (cp >= 0xff41 && cp <= 0xff5a)
  );
}

/** 从文本中提取所有「拉丁+同形字字符类」连续段（长度 ≥ 2） */
function findLatinRuns(text: string): string[] {
  const runs: string[] = [];
  let buf = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (isLatinOrHomoglyph(cp)) {
      buf += ch;
    } else {
      if (buf.length >= 2) runs.push(buf);
      buf = "";
    }
  }
  if (buf.length >= 2) runs.push(buf);
  return runs;
}

/** run 必须同时含 ASCII 拉丁与至少一个「同形字块」字符——纯 ASCII 或纯同形块都放过 */
function isMixedScript(run: string): boolean {
  let hasAscii = false;
  let hasHomoglyph = false;
  for (const ch of run) {
    const cp = ch.codePointAt(0) ?? 0;
    if (!hasAscii && (cp === 0x41 || (cp >= 0x42 && cp <= 0x5a) || cp === 0x61 || (cp >= 0x62 && cp <= 0x7a))) {
      hasAscii = true;
      continue;
    }
    if (
      !hasHomoglyph &&
      ((cp >= 0x0370 && cp <= 0x03ff) ||
        (cp >= 0x0400 && cp <= 0x04ff) ||
        (cp >= 0x1d400 && cp <= 0x1d7ff) ||
        (cp >= 0xff21 && cp <= 0xff3a) ||
        (cp >= 0xff41 && cp <= 0xff5a))
    ) {
      hasHomoglyph = true;
    }
    if (hasAscii && hasHomoglyph) return true;
  }
  return false;
}

function clipMixed(text: string, run: string): string {
  const at = text.indexOf(run);
  const start = Math.max(0, at - 15);
  const end = Math.min(text.length, at + run.length + 15);
  return text.slice(start, end).replace(/\r?\n/g, "⏎").slice(0, 80);
}

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
