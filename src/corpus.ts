import type { AssetKind, Finding, ScanResult } from "./types.js";
import { SECRET_FLAG_RE } from "./redact.js";

/**
 * 审 → 攻 语料导出（治理规则 2 的公开接口；RFC-0001 schema v2 格式）。
 *
 * 把 prompt-audit 扫出的真实投毒样本导出为 prompt-corpus-zh 的候选条目，
 * 供 InjectArena 消费（新关卡与语料素材）。导出 ≠ 入库：
 *  - 默认 `status: "pending-review"`、不写 verifiedAt——人工闸通过后才算数；
 *  - 人工闸操作员确认后用 `--verified` 导出，此时 stamped 今天日期；
 *  - flag 形状令牌在导出处确定性打码（与 InjectArena export 端点同一约定）。
 */

/** 种子规则中代表「投毒样本」的三条——sp-secret-embed 报的是凭据而非话术素材，不导出 */
const POISON_RULES = new Set(["td-injection-phrase", "td-hidden-unicode", "td-exfil-pair"]);

/** 治理规则 3：共享 attackSurface 维度（资产类型 → 语料攻击面） */
const SURFACE_BY_ASSET: Record<AssetKind, string> = {
  "tool-description": "tool-abuse",
  "mcp-config": "tool-abuse",
  "retrieved-content": "indirect-injection",
  "system-prompt": "direct-injection",
  "secret-field": "data-exfiltration",
  "guard-config": "guarded-prompt",
};

/** 命中标签 → 语料 mode 枚举（corpus/schema.json）；对不上的一律 other */
const MODE_BY_LABEL: [RegExp, string][] = [
  [/指令覆盖/, "instruction-override"],
  [/伪造权威/, "authority-forgery"],
  [/套取系统提示词/, "direct-ask"],
  [/隐藏字符/, "encoding"],
  [/读写配对/, "other"],
  [/对用户保密|绕过人工审批/, "other"],
];

export interface CorpusExport {
  generator: string;
  generatedAt: string;
  status: "pending-review" | "verified";
  entries: {
    id: string;
    attackSurface: string;
    description: string;
    payloads: {
      id: string;
      lang: "zh" | "en" | "mix";
      mode: string;
      text: string;
      source: "audit";
      verifiedAt: string | null;
      origin: { ruleId: string; file: string; line: number };
    }[];
  }[];
}

const SURFACE_LABELS: Record<string, string> = {
  "tool-abuse": "工具滥用",
  "indirect-injection": "间接注入（检索内容投毒）",
  "direct-injection": "直接注入（提示词资产）",
};

export function exportCorpus(
  results: ScanResult[],
  opts: { verified?: boolean; generator?: string } = {},
): CorpusExport {
  const payloadsBySurface = new Map<string, CorpusExport["entries"][number]["payloads"]>();
  let seq = 0;

  for (const result of results) {
    // 完整资产文本才是教学素材——告警 evidence 只是定位片段
    const assetText = new Map<string, string>();
    for (const a of result.assets) {
      if (a.text) assetText.set(`${a.file}::${a.keyPath}`, a.text);
    }
    const seen = new Set<string>();
    for (const f of result.findings) {
      if (!POISON_RULES.has(f.ruleId)) continue;
      const surface = SURFACE_BY_ASSET[f.assetKind];
      if (!payloadsBySurface.has(surface)) payloadsBySurface.set(surface, []);
      const fullText = assetText.get(`${f.file}::${f.keyPath}`);
      // 同一资产被多个模式命中只导出一条样本（文本相同，重复即噪声）
      const dedupeKey = `${surface}::${f.file}::${f.keyPath}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      payloadsBySurface.get(surface)!.push({
        id: `au-${String(++seq).padStart(3, "0")}`,
        lang: detectLang(fullText ?? f.evidence),
        mode: detectMode(f.message),
        text: redact(fullText ?? f.evidence),
        source: "audit",
        verifiedAt: opts.verified ? new Date().toISOString().slice(0, 10) : null,
        origin: { ruleId: f.ruleId, file: f.file, line: f.line },
      });
    }
  }

  const entries = [...payloadsBySurface.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([surface, payloads]) => ({
      id: `audit-${surface}`,
      attackSurface: surface,
      description: `prompt-audit 审计发现的真实投毒样本：${SURFACE_LABELS[surface] ?? surface}（${payloads.length} 条，人工闸${opts.verified ? "已通过" : "待审"}）`,
      payloads,
    }));

  return {
    generator: opts.generator ?? "prompt-audit",
    generatedAt: new Date().toISOString(),
    status: opts.verified ? "verified" : "pending-review",
    entries,
  };
}

/** flag 形状令牌确定性打码 */
export function redact(text: string): string {
  return text.replace(SECRET_FLAG_RE, "FLAG{REDACTED}");
}

/** 语种启发式：CJK 字符占比 */
export function detectLang(text: string): "zh" | "en" | "mix" {
  const cjk = (text.match(/[\u4e00-\u9fff]/g) ?? []).length;
  const latin = (text.match(/[A-Za-z]/g) ?? []).length;
  if (cjk === 0) return "en";
  if (latin === 0) return "zh";
  return "mix";
}

function detectMode(message: string): string {
  for (const [re, mode] of MODE_BY_LABEL) {
    if (re.test(message)) return mode;
  }
  return "other";
}

/** 从告警里找出可导出的样本数量（CLI 摘要用） */
export function countExportable(findings: Finding[]): number {
  return findings.filter((f) => POISON_RULES.has(f.ruleId)).length;
}
