import { describe, expect, it } from "vitest";
import { gateExit, renderPrComment } from "../src/pr-comment.js";
import { parseRepoSlug, resolvePrNumber, toAnnotations, upsertStickyComment } from "../src/github.js";
import type { Finding, ScanResult } from "../src/types.js";

function finding(sev: Finding["severity"], file = "mcp.json", line = 3): Finding {
  return {
    ruleId: "td-injection-phrase",
    severity: sev,
    file,
    line,
    keyPath: "test",
    assetKind: "tool-description",
    message: "测试告警",
    evidence: "evidence",
  };
}

function fakeResult(findings: Finding[], changed: string[] = []): ScanResult {
  return { root: ".", filesScanned: [], assets: [], findings, ignoredRules: [], git: { changedFiles: changed, untracked: [], filteredFindings: 0 } };
}

describe("gateExit（--fail-on 门禁）", () => {
  it("存在 ≥ 阈值严重度的告警即红灯", () => {
    expect(gateExit([finding("high")], "high")).toBe(1);
    expect(gateExit([finding("medium")], "high")).toBe(0);
    expect(gateExit([finding("medium")], "medium")).toBe(1);
    expect(gateExit([finding("low")], "medium")).toBe(0);
    expect(gateExit([finding("info")], "info")).toBe(1);
    expect(gateExit([], "info")).toBe(0);
  });
});

describe("renderPrComment（粘性评论正文）", () => {
  it("干净结果：标记锚点 + ✅ 文案", () => {
    const md = renderPrComment([fakeResult([], ["levels/L1.json"])], { version: "prompt-audit@0.0.1" });
    expect(md).toContain("<!-- prompt-audit-report -->");
    expect(md).toContain("✅ **AI 资产干净**");
    expect(md).toContain("levels/L1.json");
    expect(md).toContain("--fail-on high");
  });

  it("有告警：汇总行 + 明细表 + 超出 20 条折叠", () => {
    const findings = Array.from({ length: 25 }, (_, i) => finding("high", "f.json", i + 1));
    const md = renderPrComment([fakeResult(findings)], { failOn: "medium" });
    expect(md).toContain("发现 **25** 条告警");
    expect(md).toContain("| 严重度 | 位置 | 规则 | 说明 |");
    expect(md).toContain("…另有 5 条");
    expect(md).toContain("--fail-on medium");
  });

  it("消息里的竖线不破坏表格", () => {
    const md = renderPrComment([fakeResult([finding("high")])]);
    expect(md).not.toContain("测试|告警");
  });
});

describe("github 纯函数", () => {
  it("parseRepoSlug：合法与拒绝", () => {
    expect(parseRepoSlug("Croesus-K/prompt-audit")).toEqual({ owner: "Croesus-K", name: "prompt-audit" });
    expect(() => parseRepoSlug("../etc/passwd")).toThrow();
    expect(() => parseRepoSlug("a/b/c")).toThrow();
  });

  it("resolvePrNumber：显式 > 环境变量 > GITHUB_REF", () => {
    const prevRef = process.env.GITHUB_REF;
    const prevNum = process.env.GITHUB_PR_NUMBER;
    try {
      delete process.env.GITHUB_REF;
      delete process.env.GITHUB_PR_NUMBER;
      expect(resolvePrNumber()).toBeUndefined();
      process.env.GITHUB_REF = "refs/pull/42/merge";
      expect(resolvePrNumber()).toBe(42);
      process.env.GITHUB_PR_NUMBER = "7";
      expect(resolvePrNumber()).toBe(7);
      expect(resolvePrNumber("99")).toBe(99);
    } finally {
      if (prevRef !== undefined) process.env.GITHUB_REF = prevRef;
      if (prevNum !== undefined) process.env.GITHUB_PR_NUMBER = prevNum;
    }
  });

  it("toAnnotations：高危 error、其余 warning、超 10 条折叠出汇总行", () => {
    const highs = Array.from({ length: 12 }, (_, i) => finding("high", "a.json", i + 1));
    const lines = toAnnotations(highs);
    expect(lines.filter((l) => l.startsWith("::error ")).length).toBe(10);
    expect(lines.at(-1)).toContain("另有 3 条高危告警未展示");

    const mixed = [finding("high"), finding("medium"), finding("low")];
    const lines2 = toAnnotations(mixed);
    expect(lines2.filter((l) => l.startsWith("::error ")).length).toBe(1);
    expect(lines2.filter((l) => l.startsWith("::warning ")).length).toBe(2);
  });
});

describe("upsertStickyComment（注入 fetch）", () => {
  function mockFetch(responses: { status: number; body: unknown }[]) {
    const calls: { url: string; init: RequestInit }[] = [];
    const impl = (async (url: string | URL, init: RequestInit = {}) => {
      calls.push({ url: String(url), init });
      const r = responses.shift() ?? { status: 200, body: {} };
      return new Response(JSON.stringify(r.body), { status: r.status });
    }) as typeof fetch;
    return { impl, calls };
  }

  const ctx = { token: "t", repo: "Croesus-K/playground", fetchImpl: undefined as unknown as typeof fetch };

  it("无历史评论 → POST 创建", async () => {
    const { impl, calls } = mockFetch([{ status: 200, body: [] }, { status: 201, body: {} }]);
    ctx.fetchImpl = impl;
    const r = await upsertStickyComment(ctx, 5, "<!-- prompt-audit-report -->\n报告");
    expect(r).toBe("created");
    expect(calls[0].url).toContain("/repos/Croesus-K/playground/issues/5/comments");
    expect(calls[1].init.method).toBe("POST");
  });

  it("已有带标记评论 → PATCH 更新，不新建", async () => {
    const { impl, calls } = mockFetch([
      { status: 200, body: [{ id: 77, body: "旧\n<!-- prompt-audit-report -->" }] },
      { status: 200, body: {} },
    ]);
    ctx.fetchImpl = impl;
    const r = await upsertStickyComment(ctx, 5, "新报告");
    expect(r).toBe("updated");
    expect(calls[1].init.method).toBe("PATCH");
    expect(calls[1].url).toContain("/comments/77");
  });

  it("第一页 100 条无标记 → 翻页查找", async () => {
    const page1 = Array.from({ length: 100 }, (_, i) => ({ id: i, body: "无关" }));
    const { impl, calls } = mockFetch([
      { status: 200, body: page1 },
      { status: 200, body: [{ id: 555, body: "<!-- prompt-audit-report --> 旧" }] },
      { status: 200, body: {} },
    ]);
    ctx.fetchImpl = impl;
    const r = await upsertStickyComment(ctx, 5, "新");
    expect(r).toBe("updated");
    expect(calls[1].url).toContain("page=2");
  });

  it("非 2xx 抛可读错误", async () => {
    const { impl } = mockFetch([{ status: 403, body: { message: "Bad credentials" } }]);
    ctx.fetchImpl = impl;
    await expect(upsertStickyComment(ctx, 5, "x")).rejects.toThrow(/HTTP 403/);
  });
});
