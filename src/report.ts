import type { ScanResult } from "./types.js";
import { mdCell } from "./sanitize.js";

export interface RenderOptions {
  /** 报告标题（如「bounty-guard」） */
  title?: string;
}

export function renderJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function renderMarkdown(result: ScanResult, opts: RenderOptions = {}): string {
  const lines: string[] = [];
  const bySeverity = (sev: string) => result.findings.filter((f) => f.severity === sev).length;

  lines.push(`# prompt-audit 扫描输出 — ${opts.title ?? result.root}`);
  lines.push("");
  lines.push(`- 扫描根目录：\`${result.root}\``);
  lines.push(`- 检出资产的文件：${result.filesScanned.length} 个`);
  lines.push(`- 检出资产：${result.assets.length} 个`);
  lines.push(`- 忽略规则：${result.ignoredRules.length ? result.ignoredRules.join(", ") : "无"}`);
  lines.push(
    `- 告警：**${result.findings.length} 条**（高危 ${bySeverity("high")} / 中危 ${bySeverity("medium")} / 低危 ${bySeverity("low")}）`,
  );
  lines.push("");

  lines.push("## 资产盘点");
  lines.push("");
  lines.push("| 类型 | 位置 | 路径 | 摘要 |");
  lines.push("|---|---|---|---|");
  for (const a of result.assets) {
    lines.push(`| ${kindLabel(a.kind)} | \`${a.file}:${a.line}\` | \`${a.keyPath}\` | ${summarize(a)} |`);
  }
  if (result.assets.length === 0) lines.push("| （无） | | | |");
  lines.push("");

  lines.push("## 告警明细");
  lines.push("");
  if (result.findings.length === 0) {
    lines.push("无告警。");
  } else {
    lines.push("| # | 规则 | 严重度 | 位置 | 说明 | 证据 |");
    lines.push("|---|---|---|---|---|---|");
    result.findings.forEach((f, i) => {
      lines.push(
        `| ${i + 1} | \`${f.ruleId}\` | ${f.severity} | \`${f.file}:${f.line}\` | ${mdCell(f.message)} | \`${mdCell(f.evidence, 80)}\` |`,
      );
    });
  }
  lines.push("");
  return lines.join("\n");
}

function kindLabel(kind: string): string {
  const map: Record<string, string> = {
    "mcp-config": "MCP 配置",
    "tool-description": "工具描述",
    "system-prompt": "System Prompt",
    "retrieved-content": "检索内容",
    "secret-field": "秘密字段",
    "guard-config": "守方关键词",
  };
  return map[kind] ?? kind;
}

function summarize(a: { text?: string; obj?: unknown; extra?: Record<string, unknown> }): string {
  if (typeof a.extra?.tool === "string") return `工具 \`${a.extra.tool}\``;
  if (typeof a.extra?.server === "string") return `server \`${a.extra.server}\``;
  if (typeof a.extra?.title === "string") return `文档「${a.extra.title}」`;
  if (Array.isArray(a.extra?.patterns)) return `关键词 ${(a.extra.patterns as unknown[]).length} 个`;
  if (a.text) {
    const head = a.text.replace(/\r?\n/g, " ").trim().slice(0, 30);
    return `${head}${a.text.length > 30 ? "…" : ""}（${a.text.length} 字）`;
  }
  return "";
}
