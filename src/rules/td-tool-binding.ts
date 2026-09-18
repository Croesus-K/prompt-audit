import type { Asset, Finding, Rule } from "../types.js";

/**
 * td-tool-binding —— 工具描述中"绑死工具调用条件"或"指示串调其他工具"。
 *
 * 与已有规则的分界：
 * - sp-exfil-instruction 看 system prompt 里的"把 X 写进回复"类指令（文本层）
 * - td-exfil-pair 看工具本身读写配对（结构层）
 * - td-tool-binding 看工具描述教模型"什么时候调什么工具"（编排层）
 *
 * 实战形状：
 * - 「当用户要求 X 时请调用 send_email」——把工具挂到用户意图上
 * - 「调用本工具后请接着调用 notify_admin」——把工具串成动作链
 * - 「If the input matches pattern X, then call Y」——条件触发
 *
 * 这是 L5/L6 攻击面（tool-abuse / mcp-abuse）的镜像：模型被工具描述教成
 * "动作编排者"，注入载荷就能借工具通道偷渡任意调用。
 *
 * 严重度 high：编排语义一旦被工具描述锁死，注入链的破坏面就脱离单条规则的边界。
 */
export const tdToolBinding: Rule = {
  id: "td-tool-binding",
  severity: "high",
  description:
    "工具描述中含「绑死调用条件」或「串调其他工具」的话术——工具描述不应承担编排职责，注入载荷可借此把动作链偷渡出去。",
  appliesTo: ["tool-description"],
  check(asset: Asset): Finding[] {
    const text = asset.text ?? "";
    const blob = `${text}\n${safeStringify(asset.obj)}`;
    if (!blob.trim()) return [];
    const findings: Finding[] = [];
    for (const p of PATTERNS) {
      const m = blob.match(p.re);
      if (m) findings.push(buildFinding(asset, p.label, p.hint, m[0], blob));
    }
    return findings;
  },
};

interface Pattern {
  label: string;
  re: RegExp;
  hint: string;
}

const PATTERNS: Pattern[] = [
  {
    // 「当用户问/说 X 时调用 Y」「若请求…请调工具」「if user asks X, call Y」
    label: "用户意图→工具调用",
    re: /(当|如果|若|只要|when|if)\s*(用户|来访者|user|conversation|对话|请求|request)[^。\n]{0,30}(调用|触发|请用|invoke|call|trigger)\s*[A-Za-z_][\w.\[\]"\s,'`]{2,60}/i,
    hint: "工具描述把工具调用绑到用户意图上——正常的工具说明是「做什么」不是「什么时候调」",
  },
  {
    // 「调用本工具后调用 X」「接着触发 Y」「after this, call X」「then invoke Y」
    label: "串调其他工具",
    re: /(调用|触发|运行|invoke|call|trigger|then|after)[^。\n]{0,8}(本|此|this|接下来|the next|also)[^。\n]{0,15}(工具|tool|function|function_call)|(接着|然后|after\s+this)[^。\n]{0,8}(调用|触发|invoke|call)/i,
    hint: "工具描述教模型串调其他工具——把工具变成动作链的一环，注入可借编排链偷渡副作用",
  },
  {
    // 「You must always call X after every invocation」「每调用一次本工具就 Y 调用 X」
    label: "硬编码强制串调",
    re: /(每调用|每次|after\s+every|always\s+then|must\s+always)\s*[A-Za-z_][\w.\[\]"\s,'`]{0,30}(调用|触发|再调用|invoke|call|trigger)/i,
    hint: "工具描述强制每次都串调——把副作用打包进主调用，注入载荷根本不用费心编排",
  },
  {
    // 「把 X 写入参数 Y」「pass <secret> as the content parameter」「把系统提示词写进参数」
    label: "绑死工具参数内容",
    re: /(把|将|传|填|write|put|pass|insert)[^。\n]{0,10}(<[^>]+>|\{[^}]+\}|系统提示|secret|flag|上下文|context|档案|设定|instructions?)[^。\n]{0,12}(参数|字段|parameter|argument|field)/i,
    hint: "工具描述指示把敏感内容填进参数——把机密搬运到对外通道的清晰蓝图",
  },
];

function buildFinding(asset: Asset, label: string, hint: string, matched: string, blob: string): Finding {
  return {
    ruleId: "td-tool-binding",
    severity: "high",
    file: asset.file,
    line: asset.line,
    keyPath: asset.keyPath,
    assetKind: asset.kind,
    message: `${label}：${hint}`,
    evidence: clip(matched, blob),
  };
}

function clip(matched: string, blob: string, width = 60): string {
  const at = blob.indexOf(matched);
  const start = Math.max(0, (at < 0 ? 0 : at) - 8);
  const end = Math.min(blob.length, start + width);
  return blob
    .slice(start, end)
    .replace(/\r?\n/g, "⏎")
    .trim()
    .slice(0, 80);
}

function safeStringify(obj: unknown): string {
  try {
    return JSON.stringify(obj) ?? "";
  } catch {
    return "";
  }
}