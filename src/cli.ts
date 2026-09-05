import { writeFileSync } from "node:fs";
import { scan, ALL_RULE_IDS } from "./scanner.js";
import { renderJson, renderMarkdown } from "./report.js";

interface Args {
  paths: string[];
  json: boolean;
  md: boolean;
  out?: string;
  ignore: string[];
  listRules: boolean;
}

const USAGE = `prompt-audit —— AI 层安全审计（M0 原型）

用法：
  prompt-audit scan <path...> [选项]

选项：
  --json              输出 JSON（机器可读）
  --md                输出 Markdown 报告
  --out <file>        写入文件而非 stdout
  --ignore <ruleId>   忽略指定规则（可重复）
  --list-rules        列出规则集后退出
规则：${ALL_RULE_IDS.join(", ")}`;

function parseArgs(argv: string[]): Args {
  const args: Args = { paths: [], json: false, md: false, ignore: [], listRules: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "scan":
        break;
      case "--json":
        args.json = true;
        break;
      case "--md":
        args.md = true;
        break;
      case "--out":
        args.out = argv[++i];
        break;
      case "--ignore":
        args.ignore.push(argv[++i]);
        break;
      case "--list-rules":
        args.listRules = true;
        break;
      default:
        if (a.startsWith("--")) throw new Error(`未知选项：${a}`);
        args.paths.push(a);
    }
  }
  return args;
}

function main(): number {
  const args = parseArgs(process.argv.slice(2));
  if (args.listRules) {
    for (const id of ALL_RULE_IDS) console.log(id);
    return 0;
  }
  if (args.paths.length === 0) {
    console.error(USAGE);
    return 2;
  }
  for (const id of args.ignore) {
    if (!ALL_RULE_IDS.includes(id)) {
      console.error(`未知规则：${id}（可用：${ALL_RULE_IDS.join(", ")}）`);
      return 2;
    }
  }

  for (const p of args.paths) {
    const result = scan(p, { ignoredRules: args.ignore });
    const output = args.json
      ? renderJson(result)
      : renderMarkdown(result, { title: p });
    if (args.out) writeFileSync(args.out, output, "utf8");
    else console.log(output);
  }
  return 0;
}

process.exit(main());
