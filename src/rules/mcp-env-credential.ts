import type { Asset, Finding, Rule } from "../types.js";
import { matchStrongSecretShape } from "./sp-secret-embed.js";

/**
 * mcp-env-credential —— mcp.json env 块内嵌明文凭据。
 * 这是 v0.1.0 时的真实盲区：JSON 形态的 mcp-config 资产只有 obj 没有 text，
 * 所有文本规则对它失效；而 extract.ts 的 SECRET_KEYS 只认精确键名，
 * `OPENAI_API_KEY` 这类 env 名不在其列——「把真 key 写进 mcp.json 提交进仓库」
 * 是 MCP 生态最高频的真实泄露路径，此前完全漏检。
 *
 * 判定（结构化，双通道）：
 * ① env 名是凭据命名（API_KEY/SECRET/TOKEN/PASSWORD/…）且值非引用、非占位；
 * ② env 值本身命中强密钥形状（sk-…/ghp_…/AKIA… 等，复用 sp-secret-embed）。
 * 只扫结构化 obj，md 片段形态（有 text）仍由 sp-secret-embed 兜底，不重复告警。
 */
export const mcpEnvCredential: Rule = {
  id: "mcp-env-credential",
  severity: "high",
  description:
    "MCP server 配置的 env 里内嵌明文凭据——mcp.json 通常随仓库提交，env 里的真 key 等于直接进 git 历史。",
  appliesTo: ["mcp-config"],
  check(asset: Asset): Finding[] {
    const env = envOf(asset.obj);
    if (!env) return [];
    const findings: Finding[] = [];
    for (const [name, value] of Object.entries(env)) {
      if (typeof value !== "string" || value.length === 0) continue;
      const shape = matchStrongSecretShape(value);
      const credName = CRED_NAME_RE.test(name);
      if (!shape && !credName) continue;
      if (isReferenceOrPlaceholder(value)) continue;
      const why = shape ? `值命中${shape}` : "凭据命名 env";
      findings.push({
        ruleId: "mcp-env-credential",
        severity: "high",
        file: asset.file,
        line: asset.line,
        keyPath: `${asset.keyPath}.env.${name}`,
        assetKind: asset.kind,
        message: `MCP server「${serverName(asset)}」env「${name}」内嵌明文凭据（${why}）`,
        evidence: `${name}=${maskValue(value)}`,
      });
    }
    return findings;
  },
};

const CRED_NAME_RE = /(API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|ACCESS_?KEY)/i;

/** 引用与占位不算内嵌：${VAR} 引用、<占位>、your-xxx、xxx…、changeme。 */
function isReferenceOrPlaceholder(v: string): boolean {
  return (
    /^\$\{[^}]*\}$/.test(v) ||
    /^<[a-z0-9 -]+>$/i.test(v) ||
    /^(your|my)?[-_ ]?(api)?[-_ ]?key[-_ ]?(here|placeholder)?$/i.test(v.trim()) ||
    /^x{3,}$/i.test(v.trim()) ||
    /^\*+$/.test(v.trim()) ||
    /^（?(示例|例如|占位|替换为)/.test(v) ||
    /^changeme$/i.test(v.trim())
  );
}

function envOf(obj: unknown): Record<string, unknown> | null {
  if (!obj || typeof obj !== "object") return null;
  const env = (obj as Record<string, unknown>).env;
  if (!env || typeof env !== "object" || Array.isArray(env)) return null;
  return env as Record<string, unknown>;
}

function serverName(asset: Asset): string {
  return (asset.extra?.server as string | undefined) ?? asset.keyPath.split(".").pop() ?? "?";
}

function maskValue(v: string): string {
  const clipped = v.length > 24 ? `${v.slice(0, 24)}…` : v;
  return clipped.replace(/\r?\n/g, "⏎");
}
