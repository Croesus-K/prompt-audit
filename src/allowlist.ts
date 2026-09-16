import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { matchGlob } from "./glob.js";

/**
 * 单条豁免条目：命中 path 模式的资产上，可豁免的规则 id 列表。
 * rules 缺省 = 该路径上**所有**规则豁免。
 */
export interface AllowEntry {
  path: string;
  rules?: string[];
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
    return { path: e.path, rules };
  });
  return { allow };
}

/**
 * 给定 (file, ruleId)，判断是否被某条 allow 条目豁免。
 * - 文件路径 glob 不命中 → 不豁免
 * - 命中且该条目 rules 缺省 → 豁免（所有规则）
 * - 命中且 ruleId 在 rules 列表里 → 豁免
 * - 命中但 ruleId 不在 rules 列表里 → 不豁免（精细白名单）
 */
export function isAllowed(config: AllowConfig, file: string, ruleId: string): boolean {
  for (const entry of config.allow) {
    if (!matchGlob(file, [entry.path])) continue;
    if (entry.rules === undefined) return true;
    if (entry.rules.includes(ruleId)) return true;
  }
  return false;
}