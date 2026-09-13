import type { Asset, AssetKind, Finding, Rule } from "../types.js";

/**
 * sp-secret-embed —— system prompt / AGENTS.md / mcp 配置里硬编码密钥。
 * 复用 bounty-guard「hardcoded-secret」的判定思路，扩展到 AI 层资产：
 * 模型能读到的东西就要当作会泄露（InjectArena L1 复盘原话）。
 */
export const spSecretEmbed: Rule = {
  id: "sp-secret-embed",
  severity: "high",
  description:
    "AI 资产里硬编码 API key / 令牌 / flag / 内网地址——提示词不是保险柜，能被读到就意味着会泄露。",
  appliesTo: ["system-prompt", "secret-field", "mcp-config"],
  check(asset: Asset): Finding[] {
    const text = asset.text ?? "";
    if (!text) return [];
    const findings: Finding[] = [];
    const reported = new Set<string>();
    for (const p of SECRET_PATTERNS) {
      if (p.kinds && !p.kinds.includes(asset.kind)) continue;
      const m = text.match(p.re);
      if (!m?.[0] || reported.has(m[0])) continue;
      if (p.embedsOther && [...reported].some((prev) => m[0].includes(prev))) continue;
      reported.add(m[0]);
      findings.push({
        ruleId: "sp-secret-embed",
        severity: "high",
        file: asset.file,
        line: asset.line,
        keyPath: asset.keyPath,
        assetKind: asset.kind,
        message: p.label(m[0]),
        evidence: clipAround(text, m[0]),
      });
    }
    return findings;
  },
};

/** 强密钥形状（真密钥特征串，不限资产类型）：供本规则与 mcp-env-credential 共用。 */
const STRONG_KEY_SHAPES: { re: RegExp; label: string }[] = [
  { re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}/, label: "OpenAI 风格 API key" },
  { re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/, label: "GitHub token" },
  { re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/, label: "GitHub fine-grained token" },
  { re: /\bAKIA[0-9A-Z]{16}\b/, label: "AWS Access Key ID" },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, label: "Slack token" },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, label: "私钥块" },
];

/**
 * 在任意文本中匹配强密钥形状，返回形如「OpenAI 风格 API key：sk-1a…9z」的
 * 描述；无命中返回 null。mcp-env-credential 用它判定 env 值是否为真凭据。
 */
export function matchStrongSecretShape(text: string): string | null {
  for (const s of STRONG_KEY_SHAPES) {
    const m = text.match(s.re);
    if (m) return `${s.label}：${mask(m[0])}`;
  }
  return null;
}

interface SecretPattern {
  re: RegExp;
  label: (matched: string) => string;
  /** 命中内容若包含已告警的敏感串（如「口令：FLAG{…}」含 FLAG{…}）则不再重复告警 */
  embedsOther?: boolean;
  /**
   * 限定适用的资产类型。「flag/键值凭据」这类形状只在提示词资产上有意义——
   * InjectArena 的 secret 字段是关卡判定用的答案钥匙（值为演练 flag），
   * 在元数据字段上开火是 M0 实测出的主要误报源（见 docs/reports/M0-02）。
   * 真密钥形状（API key/私钥）不限资产类型：答案钥匙字段里贴真密钥照样要报。
   */
  kinds?: AssetKind[];
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    re: /FLAG\{[^}\s]{4,}\}/,
    label: (m) => `受控标记/flag 内嵌于提示词资产：${mask(m)}`,
    kinds: ["system-prompt", "retrieved-content", "mcp-config", "tool-description"],
  },
  ...STRONG_KEY_SHAPES.map(
    (s): SecretPattern => ({
      re: s.re,
      label: (m) => `疑似 ${s.label}：${mask(m)}`,
    }),
  ),
  {
    re: /(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["']?[A-Za-z0-9+/_-]{12,}/i,
    label: (m) => `疑似 key=value 形式的硬编码凭据：${mask(m)}`,
    embedsOther: true,
    kinds: ["system-prompt", "retrieved-content", "mcp-config", "tool-description"],
  },
  {
    re: /(?:口令|密码|密钥|秘钥)\s*[:：=]\s*["']?[^\s"'，。]{6,}/,
    label: (m) => `疑似中文键值形式的硬编码凭据：${mask(m)}`,
    embedsOther: true,
    kinds: ["system-prompt", "retrieved-content", "mcp-config", "tool-description"],
  },
  {
    re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/,
    label: (m) => `内网地址出现在 AI 资产中：${m}`,
  },
  {
    re: /\bhttps?:\/\/[a-z0-9-]+\.(?:internal|corp|local)\b/i,
    label: (m) => `内网域名出现在 AI 资产中：${m}`,
  },
];

/** 告警展示里对疑似敏感值做部分打码：保头尾各 4 字符。 */
function mask(m: string): string {
  if (m.length <= 8) return m;
  return `${m.slice(0, 4)}…${m.slice(-4)}（长度 ${m.length}）`;
}

function clipAround(text: string, matched: string): string {
  const at = text.indexOf(matched);
  const start = Math.max(0, at - 20);
  const end = Math.min(text.length, at + matched.length + 20);
  return text.slice(start, end).replace(/\r?\n/g, "⏎").slice(0, 100);
}
