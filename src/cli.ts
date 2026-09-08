#!/usr/bin/env node
import { writeFileSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve, join } from "node:path";
import { scan, ALL_RULE_IDS } from "./scanner.js";
import { renderMarkdown } from "./report.js";
import { exportCorpus } from "./corpus.js";
import { writeBaseline } from "./rules/mcp-drift.js";
import { renderPrComment, gateExit } from "./pr-comment.js";
import { upsertStickyComment, toAnnotations, resolvePrNumber } from "./github.js";
import type { Severity } from "./types.js";
import {
  runRegression, compareBaseline, loadBaselineFile, mergeBaseline, levelFilesFromChanges, loadLevel,
} from "./regression.js";
import { createOpenAICompatible, createScriptedLlm, TokenBucketLimiter, withRateLimit } from "./llm.js";
import { fetchPrDiff, parseUnifiedDiff } from "./github.js";
import type { GitChanges } from "./gitscan.js";

const require = createRequire(import.meta.url);
const { version } = require("../package.json") as { version: string };

const FAIL_ON_VALUES: Severity[] = ["high", "medium", "low", "info"];

const USAGE = `prompt-audit —— AI 层安全审计（提示注入扫描 / MCP 安全 / prompt 回归测试）

用法：
  prompt-audit scan <path...> [选项]
  prompt-audit export-corpus <path...> [选项]
  prompt-audit pr-comment [path] [选项]     GitHub Action 内：粘性评论 + 门禁
  prompt-audit regression <repoRoot> [选项] M3 回归门禁：改守阵者 prompt 先过注入回归
  prompt-audit list-rules

scan 选项：
  --git                diff 驱动：只审 git 变更中 AI 资产的新增行
  --baseline <file>    mcp-drift：对比工具描述指纹基线
  --update-baseline <file>  扫描后刷新基线（显式确认基线变化）
  --fail-on <sev>      门禁等级 high|medium|low|info，命中即退出码 1
  --json | --md        输出格式（默认 md）
  --out <file>         写入文件而非 stdout
  --ignore <ruleId>    忽略指定规则（可重复）

export-corpus 选项（审 → 攻 语料导出，RFC-0001 v2 格式）：
  --verified           人工闸通过：条目盖上 verifiedAt（默认 pending-review）
  --out <file>         写入文件而非 stdout

pr-comment 选项（GitHub Action 用；无令牌时优雅降级为纯门禁）：
  --fail-on <sev>      门禁等级（默认 high）
  --pr <number>        PR 编号（缺省从 GITHUB_REF 推断）
  --summary            写 Job Summary 暂存文件 .prompt-audit-summary.md
  --annotations        输出 Actions 告警标注（::error / ::warning）

regression 选项（成本闸：试考小样 + 条数上限 + 令牌桶限流；LLM 为真调用）：
  --level <file|auto>  关卡文件（auto = 从 git 变更推导，默认）
  --corpus <dir>       语料目录（缺省 <repoRoot>/corpus）
  --defense <file>     布防插槽内容（缺省空 = 关卡自身 systemPrompt 即防线）
  --reject-marker <s>  提供后附带良性请求集算误杀率
  --corpus-version <s> 基线里的语料版本标识（默认 unversioned）
  --provider <kind>    script（默认，本地/CI 零成本演示）| http（BYOK 真调用）
  --script <file>      脚本回复 JSON 数组（provider=script）
  --base-url/--api-key/--model  http provider 配置（env: PROMPT_AUDIT_LLM_* → INJECTARENA_*）
  --sample <n>         试考条数小样先行
  --max-payloads <n>   单次条数上限（默认 20，硬上限 50）
  --concurrency <n>    评测并发（默认 1）
  --baseline <file>    门禁模式：低于基线即退出码 1
  --update-baseline <file>  写基线（只升不降；降需 --allow-lower）
  --allow-lower        显式允许把基线跑低（审计留痕）
  --ndjson             NDJSON 流式进度（result / surface / report）

规则：${ALL_RULE_IDS.join(", ")}`;

interface CommonArgs {
  paths: string[];
  out?: string;
  ignore: string[];
  json: boolean;
  md: boolean;
}

function parseCommon(argv: string[]): CommonArgs {
  const args: CommonArgs = { paths: [], ignore: [], json: false, md: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--json": args.json = true; break;
      case "--md": args.md = true; break;
      case "--out": args.out = argv[++i]; break;
      case "--ignore": args.ignore.push(argv[++i]); break;
      default:
        if (a.startsWith("--")) throw new Error(`未知选项：${a}`);
        args.paths.push(a);
    }
  }
  return args;
}

function emit(output: string, out?: string): void {
  if (out) writeFileSync(out, output, "utf8");
  else process.stdout.write(output + "\n");
}

function parseFailOn(v?: string): Severity {
  if (v && (FAIL_ON_VALUES as string[]).includes(v)) return v as Severity;
  throw new Error(`--fail-on 无效：${v}（可选：${FAIL_ON_VALUES.join("|")}）`);
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const cmd = argv[0];

  if (cmd === "list-rules" || argv.includes("--list-rules")) {
    for (const id of ALL_RULE_IDS) console.log(id);
    return 0;
  }
  if (!cmd || cmd === "--help" || cmd === "-h") {
    console.error(USAGE);
    return cmd ? 0 : 2;
  }

  const rest = argv.slice(1);
  for (const id of extractIgnoreIds(rest)) {
    if (!ALL_RULE_IDS.includes(id)) {
      console.error(`未知规则：${id}（可用：${ALL_RULE_IDS.join(", ")}）`);
      return 2;
    }
  }

  if (cmd === "scan") {
    const args: CommonArgs = { paths: [], ignore: [], json: false, md: false };
    let baselineFile: string | undefined;
    let updateBaseline: string | undefined;
    let gitMode = false;
    let failOn: Severity | undefined;
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      switch (a) {
        case "--git": gitMode = true; break;
        case "--baseline": baselineFile = rest[++i]; break;
        case "--update-baseline": updateBaseline = rest[++i]; break;
        case "--fail-on": failOn = parseFailOn(rest[++i]); break;
        case "--json": args.json = true; break;
        case "--md": args.md = true; break;
        case "--out": args.out = rest[++i]; break;
        case "--ignore": args.ignore.push(rest[++i]); break;
        default:
          if (a.startsWith("--")) throw new Error(`未知选项：${a}`);
          args.paths.push(a);
      }
    }
    if (args.paths.length === 0) {
      console.error(USAGE);
      return 2;
    }
    const results = args.paths.map((p) => scan(p, { ignoredRules: args.ignore, baselineFile, git: gitMode }));
    if (updateBaseline) {
      for (const r of results) writeBaseline(updateBaseline, r);
      console.error(`基线已写入 ${updateBaseline}（工具描述指纹 ${results.reduce((n, r) => n + r.assets.filter((a) => a.kind === "tool-description").length, 0)} 个）`);
    }
    // 多路径 + --out：聚合为单份输出（逐个 emit 会互相覆盖，只剩最后一个）
    let output: string;
    if (args.json) {
      output = JSON.stringify(results.length === 1 ? results[0] : results, null, 2);
    } else {
      output = results.map((r) => renderMarkdown(r, { title: r.root })).join("\n\n---\n\n");
    }
    if (args.out) writeFileSync(args.out, output + "\n", "utf8");
    else process.stdout.write(output + "\n");
    return failOn ? gateExit(results.flatMap((r) => r.findings), failOn) : 0;
  }

  if (cmd === "regression") {
    const args: CommonArgs = { paths: [], ignore: [], json: false, md: false };
    const o: Record<string, string | number | boolean | undefined> = {};
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      const val = () => rest[++i];
      switch (a) {
        case "--level": o.level = val(); break;
        case "--corpus": o.corpus = val(); break;
        case "--defense": o.defense = val(); break;
        case "--reject-marker": o.rejectMarker = val(); break;
        case "--corpus-version": o.corpusVersion = val(); break;
        case "--provider": o.provider = val(); break;
        case "--script": o.script = val(); break;
        case "--base-url": o.baseUrl = val(); break;
        case "--api-key": o.apiKey = val(); break;
        case "--model": o.model = val(); break;
        case "--sample": o.sample = Number(val()); break;
        case "--max-payloads": o.maxPayloads = Number(val()); break;
        case "--concurrency": o.concurrency = Number(val()); break;
        case "--rate-capacity": o.rateCapacity = Number(val()); break;
        case "--rate-refill": o.rateRefill = Number(val()); break;
        case "--baseline": o.baseline = val(); break;
        case "--update-baseline": o.updateBaseline = val(); break;
        case "--allow-lower": o.allowLower = true; break;
        case "--ndjson": o.ndjson = true; break;
        case "--out": args.out = val(); break;
        default:
          if (a.startsWith("--")) throw new Error(`未知选项：${a}`);
          args.paths.push(a);
      }
    }
    const repoRoot = resolve(args.paths[0] ?? ".");

    // LLM 供给：script（零成本）| http（BYOK 真调用，env 回退 PROMPT_AUDIT_LLM_* → INJECTARENA_*）
    let llm;
    if ((o.provider ?? "script") === "script") {
      const scriptFile = o.script as string | undefined;
      if (!scriptFile) throw new Error("provider=script 需要 --script <file>（JSON 数组的回复脚本）");
      llm = createScriptedLlm(JSON.parse(readFileSync(scriptFile, "utf8")) as string[]);
    } else {
      const env = (k: string) => process.env[k];
      const baseUrl = (o.baseUrl as string) ?? env("PROMPT_AUDIT_LLM_BASE_URL") ?? env("INJECTARENA_BASE_URL");
      const apiKey = (o.apiKey as string) ?? env("PROMPT_AUDIT_LLM_API_KEY") ?? env("INJECTARENA_API_KEY");
      const model = (o.model as string) ?? env("PROMPT_AUDIT_LLM_MODEL") ?? env("INJECTARENA_MODEL");
      const limiter = new TokenBucketLimiter({ capacity: Number(o.rateCapacity ?? 10), refillPerMinute: Number(o.rateRefill ?? 10) });
      llm = withRateLimit(createOpenAICompatible({ baseUrl: baseUrl ?? "", apiKey: apiKey ?? "", model: model ?? "" }), limiter);
    }

    // 关卡来源：显式 --level 或 auto（PR 上下文用 API diff——CI 检出树干净；本地用 git status）
    let levelFiles: string[] = [];
    if (o.level && o.level !== "auto") {
      const lv = String(o.level);
      levelFiles = [resolve(repoRoot, lv)]; // 相对路径按 repoRoot 解析
    } else {
      let gitChanges: GitChanges | undefined;
      const envToken = process.env.GITHUB_TOKEN;
      const envRepo = process.env.GITHUB_REPOSITORY;
      const envPr = resolvePrNumber();
      if (envToken && envRepo && envPr) {
        gitChanges = parseUnifiedDiff(await fetchPrDiff({ token: envToken, repo: envRepo }, envPr));
      }
      levelFiles = levelFilesFromChanges(repoRoot, gitChanges);
      if (levelFiles.length === 0) {
        console.error("未发现变更中的关卡文件（levels/*.json 或 corpus/*.json）；用 --level <file> 显式指定");
        return 2;
      }
    }
    const defenseFile = o.defense as string | undefined;
    const defensePrompt = defenseFile ? readFileSync(defenseFile, "utf8") : undefined;

    const onProgress = o.ndjson ? (line: Record<string, unknown>) => console.log(JSON.stringify(line)) : undefined;
    try {
      const { reports } = await runRegression({
        levelFiles,
        corpusDir: (o.corpus as string) ?? join(repoRoot, "corpus"),
        llm,
        defensePrompt,
        rejectMarker: o.rejectMarker as string | undefined,
        corpusVersion: o.corpusVersion as string | undefined,
        sample: o.sample as number | undefined,
        maxPayloads: o.maxPayloads as number | undefined,
        concurrency: o.concurrency as number | undefined,
        onProgress,
      });

      // 基线：门禁（低于基线 → 1）与更新（只升不降，降需 --allow-lower）
      let violations: ReturnType<typeof compareBaseline> = [];
      const baselineFile = o.baseline as string | undefined;
      const updateFile = o.updateBaseline as string | undefined;
      if (baselineFile) {
        const baseline = loadBaselineFile(baselineFile);
        if (baseline) violations = compareBaseline(reports, baseline);
        else console.error(`基线文件不存在（${baselineFile}）——本次仅出报告；用 --update-baseline 首建`);
      }
      if (updateFile) {
        const { baseline, lowered } = mergeBaseline(loadBaselineFile(updateFile), reports, {
          corpusVersion: (o.corpusVersion as string) ?? "unversioned",
          allowLower: Boolean(o.allowLower),
        });
        if (lowered.length > 0 && !o.allowLower) {
          for (const v of lowered) {
            console.error(`拒绝把基线跑低：${v.attackSurface} ${v.baselineBlockRate} → ${v.currentBlockRate}；确认后加 --allow-lower`);
          }
          return 1;
        }
        writeFileSync(updateFile, JSON.stringify(baseline, null, 2) + "\n", "utf8");
        console.error(`基线已写入 ${updateFile}（${baseline.entries.length} 个攻击面）`);
      }

      const summary = { tool: `prompt-audit@${version}`, kind: "regression-report", reports, violations };
      if (o.ndjson) console.log(JSON.stringify({ type: "report", ...summary }));
      else emit(JSON.stringify(summary, null, 2), args.out);

      for (const r of reports) {
        const fp = r.benign ? ` · 误杀 ${r.benign.falsePositives}/${r.benign.evaluated}` : "";
        console.error(`${r.levelId}（${r.attackSurface}，${r.payloadCount} 条）：拦截率 ${(r.attack.blockRate * 100).toFixed(1)}%${fp}`);
      }
      for (const v of violations) {
        console.error(`⛔ 门禁违规：${v.attackSurface} 拦截率 ${(v.currentBlockRate * 100).toFixed(1)}% 低于基线 ${(v.baselineBlockRate * 100).toFixed(1)}%`);
      }
      return violations.length > 0 ? 1 : 0;
    } catch (err) {
      console.error(`回归评测失败：${(err as Error).message}`);
      return 2;
    }
  }

  if (cmd === "pr-comment") {
    const args: CommonArgs = { paths: [], ignore: [], json: false, md: false };
    let failOn: Severity = "high";
    let prNumber: string | undefined;
    let summary = false;
    let annotations = false;
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      switch (a) {
        case "--fail-on": failOn = parseFailOn(rest[++i]); break;
        case "--pr": prNumber = rest[++i]; break;
        case "--summary": summary = true; break;
        case "--annotations": annotations = true; break;
        case "--json": args.json = true; break;
        case "--md": args.md = true; break;
        case "--out": args.out = rest[++i]; break;
        case "--ignore": args.ignore.push(rest[++i]); break;
        default:
          if (a.startsWith("--")) throw new Error(`未知选项：${a}`);
          args.paths.push(a);
      }
    }
    if (args.paths.length === 0) args.paths.push(".");

    // PR 上下文（CI）：diff 必须以「PR 相对基线的变更」为准（API diff）——
    // CI 检出的是干净的 merge ref，本地 git status 恒空；无 PR 上下文时降级本地 git
    const pr = resolvePrNumber(prNumber);
    const token = process.env.GITHUB_TOKEN;
    const repo = process.env.GITHUB_REPOSITORY;
    let gitChanges: GitChanges | undefined;
    let commentAction: string | null = null;
    if (token && repo && pr) {
      const diff = await fetchPrDiff({ token, repo }, pr);
      gitChanges = parseUnifiedDiff(diff);
    }
    const results = args.paths.map((p) => scan(p, { ignoredRules: args.ignore, git: true, gitChanges }));
    const comment = renderPrComment(results, { version: `prompt-audit@${version}`, failOn });
    if (summary) writeFileSync(".prompt-audit-summary.md", comment + "\n", "utf8");

    if (token && repo && pr) {
      const action = await upsertStickyComment({ token, repo }, pr, comment);
      commentAction = action;
      console.error(`粘性评论已${action === "created" ? "创建" : "更新"}（${repo}#${pr}）`);
    } else {
      console.error("降级：缺少 GITHUB_TOKEN / GITHUB_REPOSITORY / PR 编号，跳过评论，仅门禁与摘要生效");
    }
    if (annotations) {
      for (const line of toAnnotations(results.flatMap((r) => r.findings))) console.log(line);
    }
    return gateExit(results.flatMap((r) => r.findings), failOn);
  }

  if (cmd === "export-corpus") {
    const args = parseCommon(rest);
    if (args.paths.length === 0) {
      console.error(USAGE);
      return 2;
    }
    const verified = rest.includes("--verified");
    const results = args.paths.map((p) => scan(p, { ignoredRules: args.ignore }));
    const corpus = exportCorpus(results, { verified, generator: `prompt-audit@${version}` });
    const total = corpus.entries.reduce((n, e) => n + e.payloads.length, 0);
    if (args.out) {
      emit(JSON.stringify(corpus, null, 2), args.out);
      console.error(`已导出 ${total} 条候选样本（${corpus.status}）到 ${args.out}`);
    } else {
      process.stdout.write(JSON.stringify(corpus, null, 2) + "\n");
      console.error(`# ${total} 条候选样本（${corpus.status}）；用 --out <file> 落盘`, );
    }
    return 0;
  }

  console.error(USAGE);
  return 2;
}

function extractIgnoreIds(argv: string[]): string[] {
  const ids: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--ignore") ids.push(argv[i + 1] ?? "");
  }
  return ids.filter(Boolean);
}

process.exit(await main());
