import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { scan, ALL_RULE_IDS } from "./scanner.js";
import { renderJson, renderMarkdown } from "./report.js";
import { exportCorpus } from "./corpus.js";
import { writeBaseline } from "./rules/mcp-drift.js";

const require = createRequire(import.meta.url);
const { version } = require("../package.json") as { version: string };

const USAGE = `prompt-audit —— AI 层安全审计（提示注入扫描 / MCP 安全 / prompt 回归测试）

用法：
  prompt-audit scan <path...> [选项]
  prompt-audit export-corpus <path...> [选项]
  prompt-audit list-rules

scan 选项：
  --git                diff 驱动：只审 git 变更中 AI 资产的新增行
  --baseline <file>    mcp-drift：对比工具描述指纹基线
  --update-baseline <file>  扫描后刷新基线（显式确认基线变化）
  --json | --md        输出格式（默认 md）
  --out <file>         写入文件而非 stdout
  --ignore <ruleId>    忽略指定规则（可重复）

export-corpus 选项（审 → 攻 语料导出，RFC-0001 v2 格式）：
  --verified           人工闸通过：条目盖上 verifiedAt（默认 pending-review）
  --out <file>         写入文件而非 stdout

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

function main(): number {
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
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      switch (a) {
        case "--git": gitMode = true; break;
        case "--baseline": baselineFile = rest[++i]; break;
        case "--update-baseline": updateBaseline = rest[++i]; break;
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
    for (const r of results) {
      if (args.json) emit(renderJson(r), args.out);
      else emit(renderMarkdown(r, { title: r.root }), args.out);
    }
    return 0;
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

process.exit(main());
