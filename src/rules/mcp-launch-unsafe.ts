import type { Asset, Finding, Rule, Severity } from "../types.js";

/**
 * mcp-launch-unsafe —— MCP server 启动参数/环境里显式关闭安全机制。
 * 与文本规则互补：只看结构化 obj 的 args[] 与 env{}，形状固定、确定性极强，
 * 近零误报。条目来自真实生态：
 * - `--dangerously-skip-permissions` / `--yolo` / `--auto-approve` 等跳过人工审批
 * - `NODE_TLS_REJECT_UNAUTHORIZED=0` 全局关闭 TLS 校验（npm MCP server 真实事故形状）
 * - `--no-sandbox` / `--ignore-certificate-errors` 关沙箱/关证书校验
 * 沙箱类降为中危，审批/TLS 类为高危。
 */
export const mcpLaunchUnsafe: Rule = {
  id: "mcp-launch-unsafe",
  severity: "high",
  description:
    "MCP server 以关闭权限审批 / TLS 校验 / 沙箱的方式启动——这些开关把宿主机与网络的安全边界一并交出去了。",
  appliesTo: ["mcp-config"],
  check(asset: Asset): Finding[] {
    const cfg = asset.obj;
    if (!cfg || typeof cfg !== "object") return [];
    const findings: Finding[] = [];
    const where = `${asset.file}:${asset.keyPath}`;
    const server = (asset.extra?.server as string | undefined) ?? "?";

    const args = (cfg as Record<string, unknown>).args;
    if (Array.isArray(args)) {
      const seen = new Set<string>();
      for (const a of args) {
        if (typeof a !== "string") continue;
        const hit = UNSAFE_ARGS.find((u) => u.re.test(a));
        if (!hit || seen.has(hit.label)) continue;
        seen.add(hit.label);
        findings.push({
          ruleId: "mcp-launch-unsafe",
          severity: hit.severity,
          file: asset.file,
          line: asset.line,
          keyPath: `${asset.keyPath}.args`,
          assetKind: asset.kind,
          message: `MCP server「${server}」启动参数关闭安全机制：${hit.label}（${a}）`,
          evidence: `${where}.args → ${a}`,
        });
      }
    }

    const env = (cfg as Record<string, unknown>).env;
    if (env && typeof env === "object" && !Array.isArray(env)) {
      for (const [name, value] of Object.entries(env as Record<string, unknown>)) {
        const hit = UNSAFE_ENV.find((u) => u.nameRe.test(name) && (u.valueRe ? u.valueRe.test(String(value)) : true));
        if (!hit) continue;
        findings.push({
          ruleId: "mcp-launch-unsafe",
          severity: hit.severity,
          file: asset.file,
          line: asset.line,
          keyPath: `${asset.keyPath}.env.${name}`,
          assetKind: asset.kind,
          message: `MCP server「${server}」环境变量关闭安全机制：${hit.label}（${name}=${value}）`,
          evidence: `${where}.env.${name}=${value}`,
        });
      }
    }
    return findings;
  },
};

interface UnsafeEntry {
  label: string;
  severity: Severity;
}

const UNSAFE_ARGS: (UnsafeEntry & { re: RegExp })[] = [
  { re: /^--?(dangerously[-_]?skip[-_]?permissions|skip[-_]?permissions)$/, label: "跳过全部权限审批", severity: "high" },
  { re: /^--?yolo$/i, label: "YOLO 模式（跳过一切确认）", severity: "high" },
  { re: /^--?(auto[-_]?approve|full[-_]?auto)$/, label: "全自动放行（跳过人工审批）", severity: "high" },
  { re: /^--?allow[-_]?all$/, label: "全量放行所有能力", severity: "high" },
  { re: /^--?(no[-_]?sandbox|disable[-_]?gpu[-_]?sandbox)$/, label: "关闭沙箱", severity: "medium" },
  { re: /^--?(ignore[-_]?certificate[-_]?errors|insecure)$/, label: "忽略证书/TLS 校验", severity: "high" },
];

const UNSAFE_ENV: (UnsafeEntry & { nameRe: RegExp; valueRe?: RegExp })[] = [
  { nameRe: /^NODE_TLS_REJECT_UNAUTHORIZED$/, valueRe: /^0$/, label: "全局关闭 Node TLS 证书校验", severity: "high" },
  { nameRe: /^CURL_CA_BUNDLE$/, valueRe: /^\/dev\/null$/, label: "curl 证书校验指向空设备", severity: "high" },
  { nameRe: /^(GIT_SSL_NO_VERIFY|SSL_CERT_FILE)$/i, valueRe: /^(1|true|\/dev\/null)$/i, label: "关闭 TLS 证书校验", severity: "high" },
];
