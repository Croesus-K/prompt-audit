/** 严重度：与门禁阈值 --fail-on 对齐 */
export type Severity = "high" | "medium" | "low" | "info";

/**
 * AI 资产类型。prompt-audit 只审 AI 层资产——部署时真正会被送进模型上下文、
 * 或能操纵模型行为的东西；攻击语料（如 InjectArena corpus 的 payloads）是
 * 测试素材而非资产，不在扫描范围。
 */
export type AssetKind =
  /** mcpServers 配置（server 配置整体：command/args/env/描述） */
  | "mcp-config"
  /** 单个工具定义（name + description + parameters/inputSchema） */
  | "tool-description"
  /** system prompt（JSON 的 systemPrompt 字段 / AGENTS.md / CLAUDE.md 正文） */
  | "system-prompt"
  /** 检索类内容（RAG 知识库文档等会被注入上下文的外部素材） */
  | "retrieved-content"
  /** 命名为 secret/flag/token 等的独立字段（答案钥匙类数据） */
  | "secret-field"
  /** 守方关键词盘查配置（不产生告警，仅供对比分析） */
  | "guard-config";

export interface Asset {
  kind: AssetKind;
  /** 相对扫描根目录的文件路径 */
  file: string;
  /** 资产起始行（1-based；0 表示未能定位） */
  line: number;
  /** JSON 路径或 md 锚点，如 `L4.systemPrompt`、`mcpServers.bounty-guard` */
  keyPath: string;
  /** 文本类资产内容 */
  text?: string;
  /** 结构化资产（工具定义整体等） */
  obj?: unknown;
  /** 附加信息（如 guard 的 patterns、server 名称） */
  extra?: Record<string, unknown>;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  file: string;
  line: number;
  keyPath: string;
  assetKind: AssetKind;
  /** 一句话说明命中了什么 */
  message: string;
  /** 命中片段及少量上下文（换行折叠为 ⏎，超长截断） */
  evidence: string;
}

export interface Rule {
  id: string;
  severity: Severity;
  description: string;
  appliesTo: AssetKind[];
  check(asset: Asset): Finding[];
}

export interface ScanResult {
  /** 扫描根目录 */
  root: string;
  filesScanned: string[];
  assets: Asset[];
  findings: Finding[];
  /** 被显式忽略的规则 id（--ignore） */
  ignoredRules: string[];
  /** --git 模式信息（diff 驱动：只报新增行） */
  git?: {
    changedFiles: string[];
    /** 整文件视为新增的未跟踪文件 */
    untracked: string[];
    /** 被行级过滤掉的告警数 */
    filteredFindings: number;
  };
}
