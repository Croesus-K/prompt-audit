import type { Asset, Finding, Rule } from "../types.js";

/**
 * td-exfil-pair —— 单个工具同时具备「读敏感数据 + 对外发送」能力。
 * 这正是 InjectArena L5（tool-abuse）演示的伤害半径：模型持有的工具
 * 既能读到密令、又能把内容送出系统，注入指令就能把机密带出去。
 * 启发式：对工具定义整体（描述 + 参数 schema）做读写两侧短语配对。
 */
export const tdExfilPair: Rule = {
  id: "td-exfil-pair",
  severity: "high",
  description:
    "单个工具同时声明「读取/携带敏感内容」与「对外发送/上传」能力——权限爆炸半径过大，注入可驱动数据外传。",
  appliesTo: ["tool-description"],
  check(asset: Asset): Finding[] {
    const blob = `${asset.text ?? ""}\n${safeStringify(asset.obj)}`;
    if (!blob.trim()) return [];
    const readSides = READ_HINTS.filter((re) => re.test(blob));
    const sendSides = SEND_HINTS.filter((re) => re.test(blob));
    if (readSides.length === 0 || sendSides.length === 0) return [];
    return [
      {
        ruleId: "td-exfil-pair",
        severity: "high",
        file: asset.file,
        line: asset.line,
        keyPath: asset.keyPath,
        assetKind: asset.kind,
        message: `读写配对：工具同时涉及敏感内容读取（${labelOf(blob, readSides)}）与对外发送（${labelOf(blob, sendSides)}）`,
        evidence: clipPair(blob, readSides, sendSides),
      },
    ];
  },
};

const READ_HINTS: RegExp[] = [
  /全文|整份|完整内容/,
  /上下文|对话内容|conversation|context/i,
  /档案|机密|密令|口令|凭据|secret|credential|password|token/i,
  /环境变量|env(ironment)?\s*(var|变量)?/i,
  /读取|读入|读出|read\s+(file|env|data)/i,
  /文件内容|file\s*content/i,
];

const SEND_HINTS: RegExp[] = [
  /发送|发往|送出|外发|上报|上传|推送|转发/,
  /\bsend|upload|post(_|\s)?(to|url)|webhook|exfil/i,
  /https?:\/\//i,
];

function labelOf(blob: string, regexes: RegExp[]): string {
  const labels: string[] = [];
  for (const re of regexes) {
    const m = blob.match(re);
    if (m?.[0]) labels.push(m[0]);
  }
  return [...new Set(labels)].slice(0, 3).join(" / ") || "…";
}

function clipPair(blob: string, reads: RegExp[], sends: RegExp[]): string {
  const pick = (re: RegExp): string => blob.match(re)?.[0] ?? "";
  const r = pick(reads[0]);
  const s = pick(sends[0]);
  return `读侧「${r}」 × 发侧「${s}」`.slice(0, 80);
}

function safeStringify(obj: unknown): string {
  try {
    return JSON.stringify(obj) ?? "";
  } catch {
    return "";
  }
}
