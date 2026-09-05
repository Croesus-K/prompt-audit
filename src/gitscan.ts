import { execFileSync } from "node:child_process";

/**
 * diff 驱动（方案基因「只扫新增」）：解析 git 工作区变更，
 * 让扫描器只对 AI 资产的**新增行**出告警。
 */

export interface GitChanges {
  /** 变更文件（仓库相对路径，/ 分隔；不含已删除文件） */
  files: string[];
  /** 未跟踪文件（新文件，整文件视为新增） */
  untracked: Set<string>;
  /** file → 新增行号集合；未跟踪文件不在其中（用 untracked 判断） */
  addedLines: Map<string, Set<number>>;
}

export function readGitChanges(repo: string): GitChanges {
  const changes: GitChanges = { files: [], untracked: new Set(), addedLines: new Map() };
  const out = git(repo, ["status", "--porcelain", "-z"]);
  if (out === null) return changes;

  for (const entry of out.split("\0")) {
    if (entry.length < 4) continue;
    const status = entry.slice(0, 2);
    let file = entry.slice(3).replace(/\\/g, "/");
    if (status.includes("R") && file.includes(" -> ")) {
      file = file.split(" -> ")[1]; // 重命名以新路径为准，整文件视为新
    }
    if (status.includes("D") && !status.includes("R")) continue; // 删除无可审
    if (file.includes("/")) {
      // 忽略明显非 AI 资产目录，减噪
    }
    changes.files.push(file);
    if (status === "??") {
      changes.untracked.add(file);
      continue;
    }
    const diff = git(repo, ["diff", "-U0", "HEAD", "--", file]);
    if (diff === null) continue; // 无 HEAD（空仓库）→ 视为无行级信息，按整文件处理
    const lines = new Set<number>();
    for (const m of diff.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
      const start = Number(m[1]);
      const count = m[2] === undefined ? 1 : Number(m[2]);
      for (let i = 0; i < count; i++) lines.add(start + i);
    }
    changes.addedLines.set(file, lines);
  }
  return changes;
}

/** 告警是否落在新增内容上：未跟踪文件整文件算新增；其余按行号判断。 */
export function isOnAddedLines(changes: GitChanges, file: string, line: number): boolean {
  if (changes.untracked.has(file)) return true;
  const lines = changes.addedLines.get(file);
  if (!lines) return false;
  return lines.has(line);
}

function git(repo: string, args: string[]): string | null {
  try {
    return execFileSync("git", ["-C", repo, ...args], {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch {
    return null;
  }
}
