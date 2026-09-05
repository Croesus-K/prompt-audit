import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import type { Asset, Finding, ScanResult } from "../types.js";

/**
 * mcp-drift —— 工具描述指纹与基线漂移（rug pull：装时无害，更新后投毒）。
 * 跨运行状态规则：指纹（name + description + schema 的稳定哈希）存基线 JSON，
 * PR 里指纹变化即中危告警。基线由 `--update-baseline` 显式刷新——
 * 「基线只升不降需显式确认」的思路与回归门禁一致。
 */

export interface McpBaseline {
  version: 1;
  /** `${file}::${toolName}` → 指纹 */
  tools: Record<string, string>;
}

export function toolFingerprints(assets: Asset[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const a of assets) {
    if (a.kind !== "tool-description") continue;
    const tool = a.obj as Record<string, unknown>;
    const stable = stableStringify({
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
      inputSchema: tool.inputSchema,
    });
    out[`${a.file}::${a.keyPath.split(".").pop()}`] = createHash("sha256").update(stable).digest("hex");
  }
  return out;
}

export function loadBaseline(file: string): McpBaseline | null {
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8"));
    if (parsed && parsed.version === 1 && typeof parsed.tools === "object") return parsed;
  } catch {
    /* 首次运行没有基线，不算错误 */
  }
  return null;
}

export function writeBaseline(file: string, result: ScanResult): void {
  const baseline: McpBaseline = { version: 1, tools: toolFingerprints(result.assets) };
  writeFileSync(file, JSON.stringify(baseline, null, 2) + "\n", "utf8");
}

export function checkMcpDrift(result: ScanResult, baseline: McpBaseline): Finding[] {
  const findings: Finding[] = [];
  const current = toolFingerprints(result.assets);
  for (const [key, hash] of Object.entries(current)) {
    const prev = baseline.tools[key];
    if (prev !== undefined && prev !== hash) {
      const [file, tool] = key.split("::");
      const asset = result.assets.find(
        (a) => a.kind === "tool-description" && a.file === file && a.keyPath.endsWith(`.${tool}`),
      );
      findings.push({
        ruleId: "mcp-drift",
        severity: "medium",
        file,
        line: asset?.line ?? 0,
        keyPath: asset?.keyPath ?? key,
        assetKind: "tool-description",
        message: `工具「${tool}」描述/schema 指纹与基线漂移（rug pull 风险）——确认变更来源后用 --update-baseline 刷新`,
        evidence: `${hash.slice(0, 12)} ← ${prev.slice(0, 12)}`,
      });
    }
  }
  return findings;
}

/** 键排序的稳定序列化，保证指纹跨运行可复现 */
function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
