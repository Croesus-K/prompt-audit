import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { matchGlob } from "../src/glob.js";
import { loadAllowConfig, isAllowed, EMPTY_ALLOW_CONFIG, CONFIG_FILENAME } from "../src/allowlist.js";
import type { Asset, AssetKind } from "../src/types.js";

describe("matchGlob（零依赖 glob）", () => {
  it("** 跨目录段：levels/** 命中多层与零层目录", () => {
    expect(matchGlob("levels/intro.md", ["levels/**"])).toBe(true);
    expect(matchGlob("levels/sub/x.md", ["levels/**"])).toBe(true);
    expect(matchGlob("levels", ["levels/**"])).toBe(true);
    expect(matchGlob("srclevels.md", ["levels/**"])).toBe(false);
  });

  it("* 单段任意：*.json 不跨目录", () => {
    expect(matchGlob("foo.json", ["*.json"])).toBe(true);
    expect(matchGlob("sub/foo.json", ["*.json"])).toBe(false);
  });

  it("? 单字符：a?.json", () => {
    expect(matchGlob("ab.json", ["a?.json"])).toBe(true);
    expect(matchGlob("a.json", ["a?.json"])).toBe(false);
    expect(matchGlob("abc.json", ["a?.json"])).toBe(false);
  });

  it("**/foo（无前缀）跨多目录命中 foo", () => {
    expect(matchGlob("foo", ["**/foo"])).toBe(true);
    expect(matchGlob("a/b/foo", ["**/foo"])).toBe(true);
    expect(matchGlob("foo/x", ["**/foo"])).toBe(false);
  });

  it("Windows 反斜杠按 / 处理", () => {
    expect(matchGlob("levels\\intro.md", ["levels/**"])).toBe(true);
  });

  it("多模式任一命中即 true", () => {
    expect(matchGlob("a.json", ["*.json", "*.yaml"])).toBe(true);
    expect(matchGlob("a.yaml", ["*.json", "*.yaml"])).toBe(true);
    expect(matchGlob("a.txt", ["*.json", "*.yaml"])).toBe(false);
  });
});

describe("loadAllowConfig", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "prompt-audit-allowlist-"));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("配置文件不存在 → 空配置 + 无路径", () => {
    const r = loadAllowConfig(tmp);
    expect(r.config).toEqual(EMPTY_ALLOW_CONFIG);
    expect(r.path).toBeUndefined();
  });

  it("合法配置：path + 可选 rules", () => {
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({
      allow: [
        { path: "levels/**", rules: ["sp-secret-embed"] },
        { path: "docs/**" },
      ],
    }));
    const r = loadAllowConfig(tmp);
    expect(r.path).toBe(join(tmp, CONFIG_FILENAME));
    expect(r.config.allow).toEqual([
      { path: "levels/**", rules: ["sp-secret-embed"] },
      { path: "docs/**", rules: undefined },
    ]);
  });

  it("JSON 解析失败 → 显式抛错", () => {
    writeFileSync(join(tmp, CONFIG_FILENAME), "{ this is not json");
    expect(() => loadAllowConfig(tmp)).toThrow(/配置文件解析失败/);
  });

  it("根不是对象 → 显式抛错", () => {
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify(["not", "object"]));
    expect(() => loadAllowConfig(tmp)).toThrow(/根必须是 JSON 对象/);
  });

  it("allow 缺省或非数组 → 显式抛错（安全工具配置失败必须显式）", () => {
    writeFileSync(join(tmp, CONFIG_FILENAME), "{}");
    expect(() => loadAllowConfig(tmp)).toThrow(/allow 段必须是数组/);
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({ allow: "nope" }));
    expect(() => loadAllowConfig(tmp)).toThrow(/allow 段必须是数组/);
  });

  it("entry 非对象 → 显式抛错", () => {
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({ allow: ["nope"] }));
    expect(() => loadAllowConfig(tmp)).toThrow(/allow\[0\] 必须是对象/);
  });

  it("path 缺省或空 → 显式抛错", () => {
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({ allow: [{ rules: ["x"] }] }));
    expect(() => loadAllowConfig(tmp)).toThrow(/allow\[0\]\.path 必填/);
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({ allow: [{ path: "" }] }));
    expect(() => loadAllowConfig(tmp)).toThrow(/allow\[0\]\.path 必填/);
  });

  it("rules 非数组或非字符串 → 显式抛错", () => {
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({ allow: [{ path: "x/**", rules: "nope" }] }));
    expect(() => loadAllowConfig(tmp)).toThrow(/rules 必须是字符串数组/);
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({ allow: [{ path: "x/**", rules: [42] }] }));
    expect(() => loadAllowConfig(tmp)).toThrow(/rules\[0\] 必须是字符串/);
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({ allow: [{ path: "x/**", rules: [""] }] }));
    expect(() => loadAllowConfig(tmp)).toThrow(/rules\[0\] 必须是字符串/);
  });

  it("content 段合法：regex + 可选 assetKind/keyPathPrefix", () => {
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({
      allow: [
        {
          path: "levels/**",
          rules: ["sp-secret-embed"],
          content: { regex: "^FLAG\\{L[0-9]+-[0-9a-f]+\\}$", assetKind: "system-prompt" },
        },
      ],
    }));
    const r = loadAllowConfig(tmp);
    expect(r.config.allow[0].content?.regex).toBe("^FLAG\\{L[0-9]+-[0-9a-f]+\\}$");
    expect(r.config.allow[0].content?.assetKind).toBe("system-prompt");
  });

  it("content.regex 不合法 → 加载期抛错（绝不让扫描期才失败）", () => {
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({
      allow: [{ path: "x/**", content: { regex: "(unclosed" } }],
    }));
    expect(() => loadAllowConfig(tmp)).toThrow(/不是合法正则/);
  });

  it("content.regex 空字符串 → 抛错（强制配置方提供正则）", () => {
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({
      allow: [{ path: "x/**", content: { regex: "" } }],
    }));
    expect(() => loadAllowConfig(tmp)).toThrow(/content\.regex 必填/);
  });

  it("content.assetKind 非法 → 抛错", () => {
    writeFileSync(join(tmp, CONFIG_FILENAME), JSON.stringify({
      allow: [{ path: "x/**", content: { regex: "x", assetKind: "bogus" } }],
    }));
    expect(() => loadAllowConfig(tmp)).toThrow(/assetKind 必须是已知/);
  });
});

describe("isAllowed", () => {
  it("空配置：任何 (file, ruleId) 都不豁免", () => {
    expect(isAllowed(EMPTY_ALLOW_CONFIG, "levels/intro.md", "sp-secret-embed")).toBe(false);
  });

  it("rules 缺省 = 该路径所有规则豁免", () => {
    const config = { allow: [{ path: "levels/**" }] };
    expect(isAllowed(config, "levels/intro.md", "sp-secret-embed")).toBe(true);
    expect(isAllowed(config, "levels/intro.md", "td-injection-phrase")).toBe(true);
    expect(isAllowed(config, "docs/readme.md", "sp-secret-embed")).toBe(false);
  });

  it("rules 子集：仅命中列出的规则 id 才豁免", () => {
    const config = { allow: [{ path: "levels/**", rules: ["sp-secret-embed"] }] };
    expect(isAllowed(config, "levels/intro.md", "sp-secret-embed")).toBe(true);
    expect(isAllowed(config, "levels/intro.md", "td-injection-phrase")).toBe(false);
    expect(isAllowed(config, "other/x.md", "sp-secret-embed")).toBe(false);
  });

  it("多条目任一命中即豁免", () => {
    const config = {
      allow: [
        { path: "levels/**", rules: ["sp-secret-embed"] },
        { path: "docs/**" },
      ],
    };
    expect(isAllowed(config, "levels/a.md", "sp-secret-embed")).toBe(true);
    expect(isAllowed(config, "levels/a.md", "td-injection-phrase")).toBe(false);
    expect(isAllowed(config, "docs/readme.md", "td-injection-phrase")).toBe(true);
  });

  // —— v0.3.0 起：content 内容级精确豁免 ——
  // 用法：path + rules 已经决定「在该路径上这些规则可豁免」，再加 content 后
  // 还要「资产文本命中 content.regex」才真的豁免。
  // 典型：levels/** 上只豁免「演练 FLAG{...}」的真演练字段；保留同路径上
  // 出现的真密钥形态告警。

  function mkAsset(text: string, kind: AssetKind = "system-prompt", keyPath = "L1.systemPrompt"): Asset {
    return { kind, file: "levels/L1.json", line: 1, keyPath, text };
  }

  it("content 命中 → 豁免", () => {
    const config = {
      allow: [{
        path: "levels/**",
        rules: ["sp-secret-embed"],
        content: { regex: "^FLAG\\{[A-Z][0-9]+-[0-9a-f]+\\}$" },
      }],
    };
    expect(isAllowed(config, "levels/L1.json", "sp-secret-embed", mkAsset("FLAG{L1-7f3a9c2e}"), "FLAG{L1-7f3a9c2e}")).toBe(true);
  });

  it("content 按 evidence 匹配：同 asset 上 evidence A 命中、evidence B 不命中 → 仅豁免 A", () => {
    const config = {
      allow: [{
        path: "levels/**",
        rules: ["sp-secret-embed"],
        content: { regex: "^FLAG\\{OPEN-\\d+\\}$" },
      }],
    };
    const asset = mkAsset("演练 FLAG{OPEN-9921} 与真密钥 ghp_RealSecret1234567890AbCdEf");
    expect(isAllowed(config, "levels/L1.json", "sp-secret-embed", asset, "FLAG{OPEN-9921}")).toBe(true);
    expect(isAllowed(config, "levels/L1.json", "sp-secret-embed", asset, "ghp_RealSecret1234567890AbCdEf")).toBe(false);
  });

  it("content 不命中 → 不豁免（同文件同规则但文本不是演练 flag）", () => {
    const config = {
      allow: [{
        path: "levels/**",
        rules: ["sp-secret-embed"],
        content: { regex: "^FLAG\\{[A-Z][0-9]+-[0-9a-f]+\\}$" },
      }],
    };
    expect(isAllowed(config, "levels/L1.json", "sp-secret-embed", mkAsset("ghp_realApiKey1234567890"), "ghp_realApiKey1234567890")).toBe(false);
  });

  it("content.assetKind 不匹配 → 不豁免", () => {
    const config = {
      allow: [{
        path: "levels/**",
        rules: ["sp-secret-embed"],
        content: { regex: "FLAG", assetKind: "system-prompt" },
      }],
    };
    expect(isAllowed(config, "levels/L1.json", "sp-secret-embed", mkAsset("FLAG{L1-x}", "secret-field"), "FLAG{L1-x}")).toBe(false);
    expect(isAllowed(config, "levels/L1.json", "sp-secret-embed", mkAsset("FLAG{L1-x}", "system-prompt"), "FLAG{L1-x}")).toBe(true);
  });

  it("content.keyPathPrefix 不匹配 → 不豁免", () => {
    const config = {
      allow: [{
        path: "levels/**",
        rules: ["sp-secret-embed"],
        content: { regex: "FLAG", keyPathPrefix: "L1." },
      }],
    };
    expect(isAllowed(config, "levels/L1.json", "sp-secret-embed", mkAsset("FLAG{x}", "system-prompt", "L5.systemPrompt"), "FLAG{x}")).toBe(false);
    expect(isAllowed(config, "levels/L1.json", "sp-secret-embed", mkAsset("FLAG{x}", "system-prompt", "L1.systemPrompt"), "FLAG{x}")).toBe(true);
  });

  it("content 存在但 asset 缺省（v0.2 旧调用方式） → 不豁免（保守失败）", () => {
    const config = {
      allow: [{
        path: "levels/**",
        rules: ["sp-secret-embed"],
        content: { regex: "FLAG" },
      }],
    };
    // 不传 asset → 不豁免（让显式 content 必须配 asset 才有意义）
    expect(isAllowed(config, "levels/L1.json", "sp-secret-embed")).toBe(false);
  });
});