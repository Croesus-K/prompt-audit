import { logLine } from "./sanitize.js";
import type { GitChanges } from "./gitscan.js";

/**
 * GitHub REST 交互（零依赖 fetch 封装）——形态照搬 bounty-guard/src/github.ts：
 * 粘性评论（分页查找带标记的历史评论，找到则更新）、Actions 告警标注、
 * PR 编号解析。fetch 可注入以便测试；所有请求带确定性超时。
 */

const DEFAULT_TIMEOUT_MS = 30_000;

export interface GithubContext {
  token: string;
  /** 仓库 slug：owner/name */
  repo: string;
  /** fetch 注入点（测试用）；缺省用全局 fetch */
  fetchImpl?: typeof fetch;
  /** 单次 API 请求超时（毫秒），默认 30 秒 */
  timeoutMs?: number;
}

/** 粘性评论标记：跨页查找的唯一锚点 */
export const COMMENT_MARKER = "<!-- prompt-audit-report -->";

async function request(ctx: GithubContext, url: string, init: RequestInit = {}): Promise<Response> {
  const timeoutMs = ctx.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`GitHub API 请求超时（${timeoutMs}ms）`));
    }, timeoutMs);
  });
  // 认证统一在请求层注入（SEC/演示复盘：调用点各自带头会漏——401 "Requires authentication"）
  const headers = { Authorization: `Bearer ${ctx.token}`, ...(init.headers ?? {}) };
  try {
    const pending = (ctx.fetchImpl ?? fetch)(url, { ...init, headers, signal: controller.signal });
    pending.catch(() => {}); // 防 timeout 赢得竞速后出现未处理拒绝
    return (await Promise.race([pending, timeout])) as Response;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function assertOk(path: string, res: Response): Promise<void> {
  if (res.ok) return;
  let body = "";
  try {
    body = await res.text();
  } catch {
    body = "";
  }
  const hint = res.status === 403 ? "（常见原因：令牌权限不足或触发限流）" : "";
  throw new Error(`GitHub API ${path} 失败：HTTP ${res.status}${hint}${body ? `：${body.slice(0, 200)}` : ""}`);
}

async function githubJson<T>(ctx: GithubContext, url: string, init: RequestInit = {}): Promise<T> {
  const res = await request(ctx, url, init);
  const path = url.replace("https://api.github.com", "");
  await assertOk(path, res);
  return (await res.json()) as T;
}

/** 校验并拆分 owner/name——URL 只允许由合法标识构成，杜绝路径被拼出预期范围 */
export function parseRepoSlug(repo: string): { owner: string; name: string } {
  const m = repo.match(/^([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)\/([A-Za-z0-9._-]+)$/);
  if (!m) throw new Error(`仓库标识无效：${repo}（应为 owner/name 形式）`);
  return { owner: m[1], name: m[2] };
}

function assertPrNumber(prNumber: number): number {
  if (!Number.isInteger(prNumber) || prNumber <= 0) throw new Error(`PR 编号无效：${prNumber}`);
  return prNumber;
}

function repoApiUrl(ctx: GithubContext, sub: string): string {
  const { owner, name } = parseRepoSlug(ctx.repo);
  return new URL(
    `repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}${sub}`,
    "https://api.github.com",
  ).toString();
}

/** 读取 PR 的 unified diff（REST 原生支持）：CI 里工作树是干净的 merge ref，
 * diff 驱动必须以「PR 相对基线的变更」为准——这是 bounty-guard 的原设计。 */
export async function fetchPrDiff(ctx: GithubContext, prNumber: number): Promise<string> {
  const pr = assertPrNumber(prNumber);
  const url = repoApiUrl(ctx, `/pulls/${pr}`);
  const res = await request(ctx, url, {
    headers: { Authorization: `Bearer ${ctx.token}`, Accept: "application/vnd.github.diff" },
  });
  await assertOk(url.replace("https://api.github.com", ""), res);
  return res.text();
}

/** 解析 unified diff → 变更结构（与 gitscan 的 GitChanges 同形状）。
 * 仅「+」行计为新增（上下文行只推进游标）；新增文件（--- /dev/null）整文件视为新增行。 */
export function parseUnifiedDiff(diff: string): GitChanges {
  const changes: GitChanges = { files: [], untracked: new Set(), addedLines: new Map() };
  let current: string | null = null;
  let isNew = false;
  let newLine = 0;
  let inHunk = false;
  for (const line of diff.split("\n")) {
    if (line.startsWith("diff --git")) {
      current = null;
      inHunk = false;
      continue;
    }
    if (line.startsWith("--- ")) {
      isNew = line.startsWith("--- /dev/null");
      continue;
    }
    if (line.startsWith("+++ ")) {
      const m = line.match(/^\+\+\+ b\/(.+)$/);
      if (m) {
        current = m[1].replace(/\\/g, "/");
        if (!changes.files.includes(current)) changes.files.push(current);
        if (isNew) changes.untracked.add(current);
      }
      continue;
    }
    const hunk = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
    if (hunk && current) {
      inHunk = true;
      newLine = Number(hunk[1]);
      if (!changes.addedLines.has(current)) changes.addedLines.set(current, new Set());
      continue;
    }
    if (!inHunk || !current) continue;
    if (line.startsWith("+")) {
      changes.addedLines.get(current)!.add(newLine);
      newLine += 1;
    } else if (line.startsWith("-") || line.startsWith("\\")) {
      // 旧文件行 / "\ No newline"：游标不动
    } else {
      // 上下文行：推进新文件侧游标
      newLine += 1;
    }
  }
  return changes;
}

interface IssueComment {
  id: number;
  body?: string;
}

/** 粘性评论：跨页查找带标记的历史评论，找到则更新，找不到才新建（重复扫描不刷屏） */
export async function upsertStickyComment(
  ctx: GithubContext,
  prNumber: number,
  body: string,
  marker: string = COMMENT_MARKER,
): Promise<"created" | "updated"> {
  const pr = assertPrNumber(prNumber);
  const base = repoApiUrl(ctx, `/issues/${pr}`);
  let page = 1;
  let existing: IssueComment | undefined;
  for (;;) {
    const comments = await githubJson<IssueComment[]>(ctx, `${base}/comments?per_page=100&page=${page}`);
    if (!Array.isArray(comments) || comments.length === 0) break;
    existing = comments.find((c) => typeof c.body === "string" && c.body.includes(marker));
    if (existing || comments.length < 100 || page >= 10) break;
    page++;
  }
  if (existing) {
    await githubJson(ctx, `${base}/comments/${existing.id}`, {
      method: "PATCH",
      body: JSON.stringify({ body }),
    });
    return "updated";
  }
  await githubJson(ctx, `${base}/comments`, {
    method: "POST",
    body: JSON.stringify({ body }),
  });
  return "created";
}

/** 每步标注上限：GitHub 仅接受 10 条 error + 10 条 warning，超出部分被静默丢弃 */
const ANNOTATION_CAP = 10;

/** 生成 Actions 告警标注（高危 error，其余 warning）。溢出时保留汇总条目。
 * message/file 来自不受信仓库内容（SEC-001）：过 logLine 净化，防换行伪造工作流命令。 */
export function toAnnotations(findings: FindingLike[]): string[] {
  const lines: string[] = [];
  const emit = (list: FindingLike[], level: "error" | "warning", scope: string) => {
    const head = list.slice(0, ANNOTATION_CAP - 1);
    const dropped = list.length - head.length;
    for (const f of head) {
      // file= 参数按逗号分参数——文件名里的逗号以 %2C 保位（罕见路径，显示退化但参数结构不破）
      const file = logLine(f.file, 120).replace(/,/g, "%2C");
      const message = logLine(`${f.ruleId}：${f.message}`);
      lines.push(`::${level} file=${file},line=${f.line}::[${f.severity}] ${message}`);
    }
    if (dropped > 0) {
      lines.push(`::${level} title=prompt-audit::另有 ${dropped} 条${scope}告警未展示，完整列表见 PR 评论`);
    }
  };
  emit(findings.filter((f) => f.severity === "high"), "error", "高危");
  emit(findings.filter((f) => f.severity !== "high"), "warning", "中低危");
  return lines;
}

export interface FindingLike {
  ruleId: string;
  severity: string;
  file: string;
  line: number;
  message: string;
}

/** 解析 PR 编号：显式参数 → GITHUB_PR_NUMBER → GITHUB_REF。
 * 不读取 GITHUB_EVENT_PATH 事件文件（env 提供的路径一律不做 fs 操作）。 */
export function resolvePrNumber(explicit?: string): number | undefined {
  if (explicit) {
    const n = Number(explicit);
    if (Number.isInteger(n) && n > 0) return n;
  }
  const envNumber = Number(process.env.GITHUB_PR_NUMBER);
  if (Number.isInteger(envNumber) && envNumber > 0) return envNumber;
  const fromRef = (process.env.GITHUB_REF ?? "").match(/^refs\/pull\/(\d+)\/merge$/);
  if (fromRef) return Number(fromRef[1]);
  return undefined;
}
