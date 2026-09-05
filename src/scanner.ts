import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, extname, basename } from "node:path";
import type { Asset, AssetKind, Finding, Rule, ScanResult } from "./types.js";
import { extractFromJson, extractFromMarkdown } from "./extract.js";
import { RULES, checkMcpShadow, sortFindings } from "./rules/index.js";

export interface ScanOptions {
  /** 忽略的规则 id（--ignore，可重复） */
  ignoredRules?: string[];
}

const JSON_SKIP = new Set(["node_modules", ".git", "dist", "out", ".venv"]);

/** 扫描一个文件/目录，收集 AI 资产并跑规则。 */
export function scan(root: string, opts: ScanOptions = {}): ScanResult {
  const absRoot = statSync(root).isDirectory() ? root : dirnameOf(root);
  const files = statSync(root).isDirectory() ? walk(root) : [root];

  const assets: Asset[] = [];
  const filesScanned: string[] = [];
  for (const file of files) {
    const rel = relative(absRoot, file).replace(/\\/g, "/");
    let raw: string;
    try {
      raw = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const ext = extname(file).toLowerCase();
    let found: Asset[] = [];
    if (ext === ".json") {
      found = extractFromJson(raw, rel);
    } else if (ext === ".md" || ext === ".markdown" || ext === ".txt") {
      found = extractFromMarkdown(raw, rel);
    }
    if (found.length > 0) {
      filesScanned.push(rel);
      assets.push(...found);
    }
  }

  const ignored = new Set(opts.ignoredRules ?? []);
  const activeRules = RULES.filter((r) => !ignored.has(r.id));
  const findings: Finding[] = [];
  for (const rule of activeRules) {
    for (const asset of assets) {
      if (!rule.appliesTo.includes(asset.kind)) continue;
      findings.push(...rule.check(asset));
    }
  }
  if (!ignored.has("mcp-shadow")) {
    checkMcpShadow(findings, { root: absRoot, filesScanned, assets, findings: [], ignoredRules: [...ignored] });
  }

  return {
    root: absRoot,
    filesScanned: filesScanned.sort(),
    assets,
    findings: sortFindings(findings),
    ignoredRules: [...ignored],
  };
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (JSON_SKIP.has(entry)) continue;
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) out.push(...walk(full));
    else if (isAssetFile(entry)) out.push(full);
  }
  return out;
}

function isAssetFile(name: string): boolean {
  const ext = extname(name).toLowerCase();
  const base = basename(name).toUpperCase();
  return (
    ext === ".json" ||
    ext === ".md" ||
    ext === ".markdown" ||
    ext === ".txt" ||
    base === "AGENTS.MD" ||
    base === "CLAUDE.MD"
  );
}

function dirnameOf(p: string): string {
  const idx = p.replace(/\\/g, "/").lastIndexOf("/");
  return idx > 0 ? p.slice(0, idx) : ".";
}

export const ALL_RULE_IDS = [...RULES.map((r) => r.id), "mcp-shadow"];
export type { AssetKind };
