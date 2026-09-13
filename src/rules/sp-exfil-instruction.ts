import type { Asset, Finding, Rule } from "../types.js";

/**
 * sp-exfil-instruction —— system prompt 里的指令式外发：要求把敏感上下文
 * （对话 / 用户输入 / 系统提示词 / 剪贴板 / 密钥…）发送、上传、上报到外部。
 * 这是提示词投毒的常见落点（话术本身不越权，但把数据通道指向外面）。
 *
 * 误报防线（M0 教训：守方提示词满是同形语句）：
 * - 只命中「敏感对象 + 外发动词」的指令形状，普通「上传文件/日志」不碰；
 * - 命中所在**整句**含拒绝/禁止/防范类字样（不要发送、要求即拒绝、保持警惕）
 *   一律放过——InjectArena 守阵者提示词大量使用防御方向同形语句；
 * - 宁可漏报（攻击者把外发指令伪装进防御句式时不报），不可误报。
 */
export const spExfilInstruction: Rule = {
  id: "sp-exfil-instruction",
  severity: "high",
  description:
    "system prompt 要求把对话 / 用户输入 / 系统提示词 / 剪贴板 / 密钥等敏感上下文外发——数据通道被指向了外部。",
  appliesTo: ["system-prompt"],
  check(asset: Asset): Finding[] {
    const text = asset.text ?? "";
    if (!text) return [];
    // 一句话只出一条告警：同一指令常同时命中把字句与被动句两个形状
    const bySentence = new Map<string, { label: string; hit: string; at: number }>();
    for (const p of EXFIL_PATTERNS) {
      const re = new RegExp(p.re.source, "g");
      for (const m of text.matchAll(re)) {
        const key = sentenceKey(text, m.index ?? 0, m[0].length);
        if (!bySentence.has(key)) bySentence.set(key, { label: p.label, hit: m[0], at: m.index ?? 0 });
      }
    }
    const findings: Finding[] = [];
    for (const { label, hit, at } of bySentence.values()) {
      if (DEFENSE_RE.test(sentenceOf(text, at, hit.length))) continue;
      findings.push({
        ruleId: "sp-exfil-instruction",
        severity: "high",
        file: asset.file,
        line: asset.line,
        keyPath: asset.keyPath,
        assetKind: asset.kind,
        message: label,
        evidence: clipAround(text, hit),
      });
    }
    return findings;
  },
};

/** 敏感对象 + 外发动词的指令形状（中文为主，附英文核心形状）。 */
const EXFIL_PATTERNS: { re: RegExp; label: string }[] = [
  {
    // 把/将 …敏感对象… 外发动词
    re: /(把|将)[^。；;\n]{0,16}(对话|聊天|用户输入|输入内容|上下文|系统提示词?|提示词|屏幕|剪贴板|环境变量|密钥|凭据|内部文档)[^。；;\n]{0,20}?(发送|上传|上报|传输|外传|发到|传到|送到|泄露给)/,
    label: "指令式外发：要求把敏感上下文发送/上传到外部",
  },
  {
    // 敏感对象 … (会|将|会被)? 外发动词 + 到/至/给（被动与无把字句）
    re: /(对话|聊天|用户输入|输入内容|上下文|系统提示词?|提示词|剪贴板|屏幕|环境变量|密钥|凭据)[^。；;\n]{0,10}(会被|会|将|需要|必须)?(发送|上传|上报|传输|外传)(到|至|给)/,
    label: "指令式外发：敏感上下文外发到指定目标",
  },
  {
    // 英文核心形状：send/post/upload/exfiltrate + 敏感对象
    re: /\b(send|post|upload|forward|exfiltrate)[^.\n]{0,24}(conversation|user (?:input|messages?)|context|system prompt|clipboard|screenshots?|credentials?|env(?:ironment)? variables?)\b/i,
    label: "指令式外发（英文形状）：send/upload sensitive context",
  },
];

/** 防御方向语句守卫：命中所在整句含这些字样则放过（守阵者提示词的主要形状）。 */
const DEFENSE_RE = /不(要|得|能|可|予)|禁止|请勿|切勿|勿|拒绝|防范|防御|警惕|留意|一律|忽略|严禁|不得|不要|do not|don'?t|never|avoid|refuse/i;

/** 取命中所在的整句（按中英句读切分）：同一句去重的 key，也是防御方向判定的范围。 */
function sentenceOf(text: string, at: number, len: number): string {
  const lineStart = text.lastIndexOf("\n", at) + 1;
  const nl = text.indexOf("\n", at + len);
  const lineEnd = nl < 0 ? text.length : nl;
  const line = text.slice(lineStart, lineEnd);
  const hitInLine = at - lineStart;
  let acc = 0;
  for (const seg of line.split(/[。；;！!？?]/)) {
    if (hitInLine < acc + seg.length) return seg;
    acc += seg.length + 1; // +1 补回被切掉的句读
  }
  return line;
}

const sentenceKey = sentenceOf;

function clipAround(text: string, matched: string): string {
  const at = text.indexOf(matched);
  const start = Math.max(0, at - 15);
  const end = Math.min(text.length, at + matched.length + 25);
  return text.slice(start, end).replace(/\r?\n/g, "⏎").slice(0, 100);
}
