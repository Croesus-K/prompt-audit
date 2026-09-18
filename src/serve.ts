/**
 * prompt-audit serve —— 本地 Web 仪表盘
 *
 * 设计目标：
 * 1. 零依赖（用 Node 内置 http 起服务；模板内联在代码里）
 * 2. 单用户 dogfood（无认证，绑 127.0.0.1）
 * 3. 静态页面 + JSON API：浏览器走 GET /, /assets.json, /findings.json, /allow.json
 * 4. 启动时扫一次，结果常驻内存；不改磁盘、不写 PR 评论、不联网
 */
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { resolve, relative } from "node:path";
import { scan } from "./scanner.js";
import { loadAllowConfig } from "./allowlist.js";

const HTML = `<!doctype html>
<html lang="zh"><head><meta charset="utf-8"><title>prompt-audit 仪表盘</title>
<style>
  body { font: 14px/1.5 system-ui, "PingFang SC", "Microsoft YaHei", sans-serif;
         margin: 24px; color: #222; max-width: 1200px; }
  h1 { font-size: 22px; margin: 0 0 8px; }
  h2 { font-size: 16px; margin: 24px 0 8px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
  .meta { color: #666; font-size: 12px; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { padding: 6px 8px; text-align: left; border-bottom: 1px solid #eee; vertical-align: top; }
  th { background: #f5f5f5; font-weight: 600; }
  .sev-high { color: #b00020; font-weight: 600; }
  .sev-medium { color: #b07000; }
  .sev-low, .sev-info { color: #666; }
  code { background: #f0f0f0; padding: 1px 4px; border-radius: 2px; font-size: 12px; }
  pre { background: #f8f8f8; padding: 8px; border-radius: 4px; overflow-x: auto; font-size: 12px; }
  .pill { display: inline-block; padding: 1px 6px; border-radius: 8px; background: #eee; font-size: 11px; }
  nav a { margin-right: 12px; }
</style></head>
<body>
<h1>prompt-audit 仪表盘</h1>
<div class="meta" id="meta"></div>
<nav><a href="/">总览</a><a href="/assets.json">资产 JSON</a><a href="/findings.json">告警 JSON</a><a href="/allow.json">豁免 JSON</a></nav>

<h2>摘要</h2>
<table><tr><th>指标</th><th>值</th></tr>
<tr><td>扫描根</td><td><code id="root"></code></td></tr>
<tr><td>扫描文件数</td><td id="files">-</td></tr>
<tr><td>检出资产数</td><td id="assets">-</td></tr>
<tr><td>告警总数</td><td id="findings">-</td></tr>
<tr><td>高危 / 中危 / 低危 / info</td><td id="sevs">-</td></tr>
<tr><td>豁免命中</td><td id="allowed">-</td></tr>
</table>

<h2>告警明细</h2>
<table><tr><th>规则</th><th>严重</th><th>文件:行</th><th>摘要</th></tr>
<tbody id="rows"></tbody></table>

<h2>资产清单</h2>
<table><tr><th>类型</th><th>路径</th><th>摘要</th></tr>
<tbody id="arows"></tbody></table>

<script>
async function load() {
  const [r, f, a, al] = await Promise.all([
    fetch("/scan.json").then(r => r.json()),
    fetch("/findings.json").then(r => r.json()),
    fetch("/assets.json").then(r => r.json()),
    fetch("/allow.json").then(r => r.json()),
  ]);
  document.getElementById("meta").textContent = "prompt-audit@" + r.version + " · " + r.scannedAt;
  document.getElementById("root").textContent = r.root;
  document.getElementById("files").textContent = r.filesScanned.length;
  document.getElementById("assets").textContent = r.assets.length;
  document.getElementById("findings").textContent = r.findings.length;
  const sevs = { high: 0, medium: 0, low: 0, info: 0 };
  for (const x of f) sevs[x.severity] = (sevs[x.severity] || 0) + 1;
  document.getElementById("sevs").textContent =
    sevs.high + " / " + sevs.medium + " / " + sevs.low + " / " + sevs.info;
  document.getElementById("allowed").textContent = al.allowedCount;
  const rows = document.getElementById("rows");
  for (const x of f) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td><code>' + x.ruleId + '</code></td>' +
      '<td class="sev-' + x.severity + '">' + x.severity + '</td>' +
      '<td><code>' + x.file + ':' + x.line + '</code></td>' +
      '<td>' + escape(x.message) + (x.evidence ? '<br><code>' + escape(x.evidence) + '</code>' : '') + '</td>';
    rows.appendChild(tr);
  }
  const arows = document.getElementById("arows");
  for (const x of a) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td><span class="pill">' + x.kind + '</span></td>' +
      '<td><code>' + x.file + '</code> · <code>' + x.keyPath + '</code></td>' +
      '<td>' + escape(x.preview || "") + '</td>';
    arows.appendChild(tr);
  }
}
function escape(s) { return String(s).replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c])); }
load();
</script>
</body></html>`;

export interface ServeOptions {
  /** 扫描根目录 */
  root: string;
  /** 监听地址（默认 127.0.0.1） */
  host?: string;
  /** 监听端口（默认 7481） */
  port?: number;
  /** 工具版本号（用于页面 header） */
  version: string;
}

/**
 * 启动一个只读 HTTP 仪表盘，绑定到本地 loopback。
 * 返回一个 Promise，resolve 时服务已经在跑（不阻塞——但要求调用方持有 server 用于关闭）。
 */
export function startServe(opts: ServeOptions): Promise<{ server: import("node:http").Server; port: number; host: string }> {
  const host = opts.host ?? "127.0.0.1";
  const port = opts.port ?? 7481;
  const root = resolve(opts.root);
  const result = scan(root);
  const allowLoad = loadAllowConfig(root);
  const allow = {
    path: allowLoad.path ?? "",
    allowedCount: result.allowConfig?.allowedFindings ?? 0,
  };

  const payload = {
    scan: { ...result, version: opts.version, scannedAt: new Date().toISOString() },
    findings: result.findings,
    assets: result.assets.map((a) => ({
      kind: a.kind, file: relative(root, a.file).replace(/\\/g, "/") || a.file,
      keyPath: a.keyPath, preview: (a.text ?? "").slice(0, 80),
    })),
    allow,
  };

  const server = createServer((req, res) => {
    const url = (req.url ?? "/").split("?")[0];
    if (url === "/" || url === "/index.html") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(HTML);
      return;
    }
    if (url === "/scan.json" || url === "/findings.json" || url === "/assets.json" || url === "/allow.json") {
      const key = url.slice(1, -5) as keyof typeof payload;
      res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
      res.end(JSON.stringify(payload[key], null, 2));
      return;
    }
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("404 Not Found");
  });

  return new Promise((resolveP, rejectP) => {
    server.once("error", rejectP);
    server.listen(port, host, () => {
      const addr = server.address();
      const actualPort = typeof addr === "object" && addr ? addr.port : port;
      resolveP({ server, port: actualPort, host });
    });
  });
}