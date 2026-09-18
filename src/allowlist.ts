import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { matchGlob } from "./glob.js";
import type { Asset, AssetKind } from "./types.js";

/**
 * 豁免内容匹配（v0.3.0 起）：命中 path + rules 后，再对资产内容做精确过滤——
 * 让豁免从「这条路径全豁免」精细到「这条路径上、这种 keyPath/资产类型里、
 * 文本含这个子串/正则的，才豁免」。典型用法：豁免特定 fixture 上的演练
 * FLAG{…}，但保留同文件里真密钥形态字符串的告警。
 */
export interface AllowContentMatch {
  /** 正则表达式；命中 asset.text 即视为匹配。空字符串视为永不匹配（强制配置方提供正则） */
  regex: string;
  /** 仅在指定资产类型上生效；缺省 = 所有 kind */
  assetKind?: AssetKind;
  /** 仅在 keyPath 以此前缀开头的资产上生效；缺省 = 全部 keyPath */
  keyPathPrefix?: string;
}

/**
 * 单条豁免条目：命中 path 模式的资产上，可豁免的规则 id 列表。
 * - rules 缺省 = 该路径上**所有**规则豁免
 * - content 存在 = 上述豁免进一步收紧到「内容正则也命中」的资产上
 */
export interface AllowEntry {
  path: string;
  rules?: string[];
  content?: AllowContentMatch;
}

export interface AllowConfig {
  allow: AllowEntry[];
}

export const EMPTY_ALLOW_CONFIG: AllowConfig = { allow: [] };

/** 配置文件名（仓库根） */
export const CONFIG_FILENAME = ".prompt-audit.json";

/**
 * 读取并校验 <root>/.prompt-audit.json。
 * - 不存在 → 空配置
 * - 损坏或形状不合法 → 抛错（安全工具配置失败必须显式，绝不静默——failOn 写错却照常放行是大忌）
 */
export function loadAllowConfig(root: string): { config: AllowConfig; path?: string } {
  const configPath = join(root, CONFIG_FILENAME);
  if (!existsSync(configPath)) return { config: EMPTY_ALLOW_CONFIG };
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(configPath, "utf8"));
  } catch {
    throw new Error(`配置文件解析失败：${configPath}`);
  }
  return { config: validateAllowConfig(raw, configPath), path: configPath };
}

function validateAllowConfig(raw: unknown, sourcePath: string): AllowConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`${sourcePath}：根必须是 JSON 对象`);
  }
  const r = raw as Record<string, unknown>;
  if (!Array.isArray(r.allow)) {
    throw new Error(`${sourcePath}：allow 段必须是数组（缺省或写错都会让豁免静默失效）`);
  }
  const allow: AllowEntry[] = r.allow.map((entry, i) => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new Error(`${sourcePath}：allow[${i}] 必须是对象`);
    }
    const e = entry as Record<string, unknown>;
    if (typeof e.path !== "string" || e.path.length === 0) {
      throw new Error(`${sourcePath}：allow[${i}].path 必填且为非空字符串`);
    }
    let rules: string[] | undefined;
    if (e.rules !== undefined) {
      if (!Array.isArray(e.rules)) {
        throw new Error(`${sourcePath}：allow[${i}].rules 必须是字符串数组`);
      }
      rules = e.rules.map((rid, j) => {
        if (typeof rid !== "string" || rid.length === 0) {
          throw new Error(`${sourcePath}：allow[${i}].rules[${j}] 必须是字符串`);
        }
        return rid;
      });
    }
    let content: AllowContentMatch | undefined;
    if (e.content !== undefined) {
      content = validateContentMatch(e.content, sourcePath, i);
    }
    return { path: e.path, rules, content };
  });
  return { allow };
}

function validateContentMatch(raw: unknown, sourcePath: string, i: number): AllowContentMatch {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`${sourcePath}：allow[${i}].content 必须是对象`);
  }
  const c = raw as Record<string, unknown>;
  if (typeof c.regex !== "string" || c.regex.length === 0) {
    throw new Error(`${sourcePath}：allow[${i}].content.regex 必填且为非空字符串`);
  }
  // 预编译校验：坏的 regex 在加载期失败，绝不让扫描期才抛错
  try {
    new RegExp(c.regex);
  } catch (err) {
    throw new Error(`${sourcePath}：allow[${i}].content.regex 不是合法正则：${(err as Error).message}`);
  }
  if (c.assetKind !== undefined) {
    const kinds: AssetKind[] = [
      "mcp-config",
      "tool-description",
      "system-prompt",
      "retrieved-content",
      "secret-field",
      "guard-config",
    ];
    if (typeof c.assetKind !== "string" || !(kinds as string[]).includes(c.assetKind)) {
      throw new Error(`${sourcePath}：allow[${i}].content.assetKind 必须是已知 AssetKind`);
    }
  }
  if (c.keyPathPrefix !== undefined && (typeof c.keyPathPrefix !== "string" || c.keyPathPrefix.length === 0)) {
    throw new Error(`${sourcePath}：allow[${i}].content.keyPathPrefix 必须是字符串`);
  }
  return {
    regex: c.regex,
    assetKind: c.assetKind as AssetKind | undefined,
    keyPathPrefix: c.keyPathPrefix as string | undefined,
  };
}

/**
 * 给定 (file, ruleId, asset?, evidence?)，判断是否被某条 allow 条目豁免。
 * 判定按 entry 顺序短路：
 *   1. 文件路径 glob 不命中 → 不豁免
 *   2. rules 缺省 → 通过；rules 显式给出 → ruleId 必须在列表里
 *   3. content 存在 → 进一步要求 finding evidence 命中正则 + assetKind/keyPathPrefix 范围匹配
 *      （按 evidence 而非整段 asset.text 匹配——同一资产上可能有多条发现，
 *      只豁免 evidence 命中 content.regex 的那一条；其余发现不受影响）
 */
export function isAllowed(
  config: AllowConfig,
  file: string,
  ruleId: string,
  asset?: Asset,
  evidence?: string,
): boolean {
  for (const entry of config.allow) {
    if (!matchGlob(file, [entry.path])) continue;
    if (entry.rules !== undefined && !entry.rules.includes(ruleId)) continue;
    if (entry.content && !matchesContent(entry.content, asset, evidence)) continue;
    return true;
  }
  return false;
}

function matchesContent(content: AllowContentMatch, asset: Asset | undefined, evidence: string | undefined): boolean {
  if (!asset) return false;
  if (content.assetKind && asset.kind !== content.assetKind) return false;
  if (content.keyPathPrefix && !asset.keyPath.startsWith(content.keyPathPrefix)) return false;
  const haystack = evidence ?? asset.text ?? "";
  if (haystack.length === 0) return false;
  let re: RegExp;
  try {
    re = new RegExp(content.regex);
  } catch {
    return false;
  }
  return re.test(haystack);
}