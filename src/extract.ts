import type { Asset, AssetKind } from "./types.js";

/** 从 JSON 文本提取 AI 资产。raw 为原始文件内容（用于行定位）。 */
export function extractFromJson(raw: string, file: string): Asset[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  const assets: Asset[] = [];
  walk(parsed, file, "", assets);
  return resolveLines(assets, raw);
}

/**
 * 从 Markdown 提取 AI 资产：
 * - 内联或围栏代码块中含 mcpServers 的 JSON 片段 → mcp-config
 * - AGENTS.md / CLAUDE.md 全文 → system-prompt
 */
export function extractFromMarkdown(raw: string, file: string): Asset[] {
  const assets: Asset[] = [];
  const base = file.replace(/\\/g, "/").split("/").pop() ?? "";
  if (/^(AGENTS|CLAUDE)\.md$/i.test(base)) {
    assets.push({
      kind: "system-prompt",
      file,
      line: 1,
      keyPath: "document",
      text: raw,
    });
    return assets;
  }
  for (const snippet of extractJsonSnippets(raw, "mcpServers")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(snippet);
    } catch {
      continue;
    }
    const line = locateLine(raw.split(/\r?\n/), `"mcpServers"`);
    assets.push({
      kind: "mcp-config",
      file,
      line,
      keyPath: "mcpServers",
      obj: parsed,
      text: snippet,
    });
  }
  return assets;
}

/**
 * 遍历 JSON 树收集资产。识别形状（而非仅按键名），避免把 package.json
 * 这类「有 name 也有 description」的普通对象误认成工具定义：
 * - mcpServers 键 → 每个server整体为 mcp-config，其下继续找工具定义
 * - { name + description + (parameters|inputSchema) } → tool-description
 * - systemPrompt 字符串字段 → system-prompt
 * - documents[].text（RAG 知识库形状）→ retrieved-content
 * - secret/flag/token/password/apiKey 等命名字符串 → secret-field
 * - { kind: "keywordBlock", patterns[] } → guard-config（不告警，供对比）
 */
function walk(node: unknown, file: string, path: string, out: Asset[]): void {
  if (Array.isArray(node)) {
    node.forEach((item, i) => walk(item, file, `${path}[${i}]`, out));
    return;
  }
  if (node === null || typeof node !== "object") return;
  const obj = node as Record<string, unknown>;

  if (typeof obj.mcpServers === "object" && obj.mcpServers !== null) {
    for (const [name, cfg] of Object.entries(obj.mcpServers as Record<string, unknown>)) {
      out.push({
        kind: "mcp-config",
        file,
        line: 0,
        keyPath: joinPath(path, `mcpServers.${name}`),
        obj: cfg,
        extra: { server: name },
      });
      walk(cfg, file, joinPath(path, `mcpServers.${name}`), out);
    }
    return;
  }

  if (typeof obj.description === "string" && typeof obj.name === "string" &&
      (typeof obj.parameters === "object" || typeof obj.inputSchema === "object")) {
    out.push({
      kind: "tool-description",
      file,
      line: 0,
      keyPath: joinPath(path, obj.name),
      obj,
      text: obj.description,
      extra: { tool: obj.name },
    });
  }

  if (typeof obj.systemPrompt === "string") {
    out.push({
      kind: "system-prompt",
      file,
      line: 0,
      keyPath: joinPath(path, "systemPrompt"),
      text: obj.systemPrompt,
    });
  }

  if (Array.isArray(obj.documents)) {
    for (const [i, doc] of (obj.documents as unknown[]).entries()) {
      if (!doc || typeof doc !== "object") continue;
      const d = doc as Record<string, unknown>;
      if (typeof d.text !== "string") continue;
      out.push({
        kind: "retrieved-content",
        file,
        line: 0,
        keyPath: joinPath(path, `documents[${i}].text`),
        text: d.text,
        extra: { title: typeof d.title === "string" ? d.title : String(d.title ?? "") },
      });
    }
  }

  if (obj.kind === "keywordBlock" && Array.isArray(obj.patterns)) {
    out.push({
      kind: "guard-config",
      file,
      line: 0,
      keyPath: joinPath(path, "guard"),
      extra: { patterns: obj.patterns },
    });
  }

  for (const [key, value] of Object.entries(obj)) {
    if (SECRET_KEYS.has(key.toLowerCase()) && typeof value === "string" && value.length > 0) {
      out.push({
        kind: "secret-field",
        file,
        line: 0,
        keyPath: joinPath(path, key),
        text: value,
        extra: { field: key },
      });
    } else if (typeof value === "object" && value !== null) {
      walk(value, file, joinPath(path, key), out);
    }
  }
}

const SECRET_KEYS = new Set(["secret", "flag", "password", "passwd", "token", "apikey", "api_key"]);

/** 用原始文本行定位资产所在行：取值的首段非换行内容做子串匹配，退化为按键名定位。 */
function resolveLines(assets: Asset[], raw: string): Asset[] {
  const lines = raw.split(/\r?\n/);
  for (const asset of assets) {
    asset.line = locateAssetLine(lines, asset);
  }
  return assets;
}

function locateAssetLine(lines: string[], asset: Asset): number {
  if (asset.text) {
    const firstChunk = asset.text.split("\n").find((s) => s.trim().length > 0);
    if (firstChunk) {
      const needle = firstChunk.trim().slice(0, 40);
      const at = lines.findIndex((l) => l.includes(needle));
      if (at >= 0) return at + 1;
    }
  }
  const lastKey = asset.keyPath.split(/[.[\]]/).filter(Boolean).pop();
  if (lastKey) {
    const at = lines.findIndex((l) => l.includes(`"${lastKey}"`));
    if (at >= 0) return at + 1;
  }
  return 0;
}

function locateLine(lines: string[], needle: string): number {
  const at = lines.findIndex((l) => l.includes(needle));
  return at >= 0 ? at + 1 : 0;
}

/** 从 md 原文中抠出含 targetKey 的平衡 JSON 片段（支持内联与围栏代码块）。 */
export function extractJsonSnippets(raw: string, targetKey: string): string[] {
  const snippets: string[] = [];
  const keyAt = raw.indexOf(`"${targetKey}"`);
  if (keyAt < 0) return snippets;
  const open = raw.lastIndexOf("{", keyAt);
  if (open < 0) return snippets;
  const end = balancedEnd(raw, open);
  if (end > open) snippets.push(raw.slice(open, end + 1));
  return snippets;
}

/** 字符串感知的平衡花括号扫描，返回与 open 配对的闭括号下标；找不到返回 -1。 */
function balancedEnd(s: string, open: number): number {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = open; i < s.length; i++) {
    const ch = s[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === '"') inString = !inString;
    if (inString) continue;
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function joinPath(base: string, key: string): string {
  return base ? `${base}.${key}` : key;
}
