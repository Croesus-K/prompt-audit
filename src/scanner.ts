import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, extname, basename } from "node:path";
import type { Asset, AssetKind, Finding, Rule, ScanResult } from "./types.js";
import { extractFromJson, extractFromMarkdown } from "./extract.js";
import { RULES, checkMcpShadow, sortFindings } from "./rules/index.js";
import { checkMcpDrift, loadBaseline } from "./rules/mcp-drift.js";
import { readGitChanges, isOnAddedLines, type GitChanges } from "./gitscan.js";

export interface ScanOptions {
  /** 忽略的规则 id（--ignore，可重复） */
  ignoredRules?: string[];
  /** mcp-drift：工具描述指纹基线文件（不存在则视为首次运行，不告警） */
  baselineFile?: string;
  /** diff 驱动：只保留落在 git 新增行上的告警 */
  git?: boolean;
  /** 预解析的变更集（CI 场景来自 PR API diff；缺省用本地 git status/diff） */
  gitChanges?: GitChanges;
}

const JSON_SKIP = new Set(["node_modules", ".git", "dist", "out", ".venv"]);
/** 单文件大小上限（SEC-001）：资产是提示词级别的文本，超限即跳过，防超大文件拖垮内存 */
const MAX_FILE_BYTES = 2 * 1024 * 1024;

/** 扫描一个文件/目录，收集 AI 资产并跑规则。 */
export function scan(root: string, opts: ScanOptions = {}): ScanResult {
  const absRoot = statSync(root).isDirectory() ? root : dirnameOf(root);
  const files = statSync(root).isDirectory() ? walk(root) : singleFile(root);

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
  const shadowResult: ScanResult = { root: absRoot, filesScanned, assets, findings: [], ignoredRules: [...ignored] };
  if (!ignored.has("mcp-shadow")) {
    checkMcpShadow(findings, shadowResult);
  }
  if (!ignored.has("mcp-drift") && opts.baselineFile) {
    const baseline = loadBaseline(opts.baselineFile);
    if (baseline) findings.push(...checkMcpDrift(shadowResult, baseline));
  }

  const result: ScanResult = {
    root: absRoot,
    filesScanned: filesScanned.sort(),
    assets,
    findings: sortFindings(findings),
    ignoredRules: [...ignored],
  };

  if (opts.git) {
    const changes = opts.gitChanges ?? readGitChanges(absRoot);
    const before = result.findings.length;
    result.findings = result.findings.filter((f) => isOnAddedLines(changes, f.file, f.line));
    result.git = {
      changedFiles: changes.files.sort(),
      untracked: [...changes.untracked].sort(),
      filteredFindings: before - result.findings.length,
    };
  }
  return result;
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const dirent of readdirSync(dir, { withFileTypes: true })) {
    // 隐藏目录（.git/.tmp/.venv…）与构建产物不进扫描面——M0 dogfood 实测扫描产物
    // JSON（.tmp/*.json）会被形状识别误当资产
    if (JSON_SKIP.has(dirent.name) || dirent.name.startsWith(".")) continue;
    // 符号链接一律跳过（SEC-001）：链接环会让递归失控，链接目标不受仓库边界约束
    if (dirent.isSymbolicLink()) continue;
    const full = join(dir, dirent.name);
    if (dirent.isDirectory()) out.push(...walk(full));
    else if (dirent.isFile() && isAssetFile(dirent.name) && statSync(full).size <= MAX_FILE_BYTES) out.push(full);
  }
  return out;
}

function singleFile(p: string): string[] {
  if (!isAssetFile(basename(p))) return [];
  try {
    if (statSync(p).size > MAX_FILE_BYTES) return [];
  } catch {
    return [];
  }
  return [p];
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

export const ALL_RULE_IDS = [...RULES.map((r) => r.id), "mcp-shadow", "mcp-drift"];
export type { AssetKind };
