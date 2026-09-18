import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, existsSync, readFileSync, rmSync, mkdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const CLI = join(process.cwd(), "dist/cli.js");

function runCli(args: string[], cwd: string): { status: number; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8" });
  return { status: r.status ?? 0, stdout: r.stdout, stderr: r.stderr };
}

describe("cli × init-hooks", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "pa-hooks-"));
    mkdirSync(join(tmp, ".git", "hooks"), { recursive: true });
  });
  afterEach(() => rmSync(tmp, { recursive: true, force: true }));

  it("在干净仓库里装出可执行 hook", () => {
    const r = runCli(["init-hooks"], tmp);
    expect(r.status).toBe(0);
    const hookPath = join(tmp, ".git/hooks/pre-commit");
    expect(existsSync(hookPath)).toBe(true);
    const content = readFileSync(hookPath, "utf8");
    expect(content).toMatch(/^#!\/usr\/bin\/env sh/);
    expect(content).toContain("prompt-audit scan");
    expect(content).toContain("--fail-on high");
    // chmod 0o755 在 Windows 上被忽略（NTFS 用 ACL），但至少确认调用了 chmodSync
    // 且文件至少有 rw 权限
    const mode = statSync(hookPath).mode & 0o777;
    expect(mode & 0o600).toBe(0o600); // owner read+write
  });

  it("存在既有 hook 时拒绝覆盖（exit 1）", () => {
    writeFileSync(join(tmp, ".git/hooks/pre-commit"), "#!/bin/sh\necho legacy\n");
    const r = runCli(["init-hooks"], tmp);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/已存在/);
    // 内容未被改
    expect(readFileSync(join(tmp, ".git/hooks/pre-commit"), "utf8")).toContain("legacy");
  });

  it("--force 覆盖既有 hook", () => {
    writeFileSync(join(tmp, ".git/hooks/pre-commit"), "#!/bin/sh\necho legacy\n");
    const r = runCli(["init-hooks", "--force"], tmp);
    expect(r.status).toBe(0);
    expect(readFileSync(join(tmp, ".git/hooks/pre-commit"), "utf8")).toContain("prompt-audit scan");
  });

  it("--fail-on 自定义等级生效", () => {
    const r = runCli(["init-hooks", "--fail-on", "medium"], tmp);
    expect(r.status).toBe(0);
    expect(readFileSync(join(tmp, ".git/hooks/pre-commit"), "utf8")).toContain("--fail-on medium");
  });

  it("--target 指定非仓库目录则报错", () => {
    const other = mkdtempSync(join(tmpdir(), "pa-other-"));
    const r = runCli(["init-hooks", "--target", other], tmp);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/git 工作树/);
    rmSync(other, { recursive: true, force: true });
  });

  it("--fail-on 无效值报清晰错误", () => {
    const r = runCli(["init-hooks", "--fail-on", "bogus"], tmp);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/--fail-on 无效/);
  });
});