import type { Asset, Finding, Rule } from "../types.js";

/**
 * td-missing-schema —— 工具定义缺参数结构（parameters / inputSchema 都没有）。
 *
 * 实战形状：开发者写 tool 时只填了 name + description 就想用，模型调用时
 * 会自己"脑补"参数形状——这种工具是注入载荷最喜欢的舞台，因为没有 schema
 * 约束，构造意外调用（拼错字段名/类型）零摩擦。
 *
 * 判定面：asset.obj 的结构化字段（仅 JSON tool-definition 资产可判；
 * 文本描述里"建议参数…"之类的自然语言措辞不算）。豁免：工具在 parameters
 * 或 inputSchema 至少一个字段下声明了任意类型（即便空 object 也算"有 schema"）。
 *
 * 严重度 medium：本身不直接是攻击面，但属于"易被利用"的结构缺陷。
 */
export const tdMissingSchema: Rule = {
  id: "td-missing-schema",
  severity: "medium",
  description:
    "工具定义缺参数结构（parameters / inputSchema 都没有）——无 schema 约束的工具让 LLM 自由发挥，注入载荷可拼错字段名/类型构造意外调用。",
  appliesTo: ["tool-description"],
  check(asset: Asset): Finding[] {
    const obj = asset.obj;
    if (!obj || typeof obj !== "object") return [];
    const o = obj as Record<string, unknown>;
    const hasParams = o.parameters !== undefined && o.parameters !== null;
    const hasInputSchema = o.inputSchema !== undefined && o.inputSchema !== null;
    if (hasParams || hasInputSchema) return [];
    const toolName = typeof o.name === "string" ? o.name : asset.extra?.tool ?? asset.keyPath;
    return [
      {
        ruleId: "td-missing-schema",
        severity: "medium",
        file: asset.file,
        line: asset.line,
        keyPath: asset.keyPath,
        assetKind: asset.kind,
        message: `工具「${toolName}」缺参数结构：未声明 parameters / inputSchema——LLM 调用时会自己脑补参数形状，注入载荷可钻此空子构造意外调用`,
        evidence: `name=${JSON.stringify(toolName)}, hasParameters=false, hasInputSchema=false`,
      },
    ];
  },
};