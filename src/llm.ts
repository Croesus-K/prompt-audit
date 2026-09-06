/**
 * LLM 供给层（M3 回归门禁的成本防线）——形态移植自 InjectArena：
 *  - TokenBucketLimiter：令牌桶限流，先于一切 LLM 调用生效
 *  - createOpenAICompatible：OpenAI 兼容协议 BYOK 适配器（重试/超时/工具包装）
 *  - createScriptedLlm：脚本化回复（本地/CI 演示与测试，零成本零网络）
 */

export interface RateCheck {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

const MAX_KEYS = 10000;

export class TokenBucketLimiter {
  capacity: number;
  refillPerMinute: number;
  private now: () => number;
  private buckets = new Map<string, { tokens: number; lastRefill: number; lastSeen: number }>();

  constructor(options: { capacity?: number; refillPerMinute?: number; now?: () => number } = {}) {
    this.capacity = (options.capacity ?? 0) > 0 ? options.capacity! : 10;
    this.refillPerMinute = (options.refillPerMinute ?? 0) > 0 ? options.refillPerMinute! : this.capacity;
    this.now = options.now ?? (() => Date.now());
  }

  check(key: string): RateCheck {
    const t = this.now();
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { tokens: this.capacity, lastRefill: t, lastSeen: t };
      this.buckets.set(key, bucket);
      if (this.buckets.size > MAX_KEYS) this.prune(t);
    } else {
      const elapsedMinutes = Math.max(0, t - bucket.lastRefill) / 60000;
      bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsedMinutes * this.refillPerMinute);
      bucket.lastRefill = t;
      bucket.lastSeen = t;
    }
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true, remaining: Math.floor(bucket.tokens), retryAfterSeconds: 0 };
    }
    const deficit = 1 - bucket.tokens;
    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.max(1, Math.ceil((deficit / this.refillPerMinute) * 60)),
    };
  }

  private prune(t: number): void {
    for (const [key, bucket] of this.buckets) {
      if (t - bucket.lastSeen > 600000) this.buckets.delete(key);
    }
  }
}

export interface LlmResult {
  text: string;
  tokens?: number;
  toolCalls?: { id: string; name: string; args: Record<string, unknown> }[];
}

export interface Llm {
  chat(messages: { role: string; content: string }[], opts?: { tools?: unknown[] }): Promise<LlmResult>;
}

export class ProviderError extends Error {
  status: number | null;
  constructor(message: string, status: number | null = null) {
    super(message);
    this.name = "ProviderError";
    this.status = status;
  }
}

function joinUrl(base: string, suffix: string): string {
  return base.replace(/\/+$/, "") + suffix;
}

export interface ProviderConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxRetries?: number;
  retryBaseMs?: number;
  temperature?: number;
  maxTokens?: number;
}

/** OpenAI 兼容协议（OpenAI / DeepSeek / GLM / Kimi / Qwen 等一切兼容服务），BYOK */
export function createOpenAICompatible(config: ProviderConfig): Llm & { model: string } {
  const { baseUrl, apiKey, model } = config;
  if (!baseUrl) throw new Error("缺少 baseUrl（OpenAI 兼容服务地址）");
  if (!apiKey) throw new Error("缺少 apiKey（BYOK：由调用方提供）");
  if (!model) throw new Error("缺少 model（如 deepseek-chat / glm-4-flash / gpt-4o-mini）");

  const fetchImpl = config.fetchImpl ?? globalThis.fetch;
  const timeoutMs = config.timeoutMs ?? 60000;
  const maxRetries = config.maxRetries ?? 2;
  const retryBaseMs = config.retryBaseMs ?? 800;
  const defaultTemperature = config.temperature ?? 0.7;
  const defaultMaxTokens = config.maxTokens ?? 1024;
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  async function chat(messages: { role: string; content: string }[], opts?: { tools?: unknown[] }): Promise<LlmResult> {
    const body: Record<string, unknown> = {
      model,
      messages,
      temperature: defaultTemperature,
      max_tokens: defaultMaxTokens,
    };
    if (Array.isArray(opts?.tools) && opts.tools.length > 0) {
      body.tools = (opts!.tools as Record<string, unknown>[]).map((t) =>
        t.type === "function" && t.function ? t : { type: "function", function: t },
      );
    }
    for (let attempt = 1; ; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let res: Response;
      try {
        res = await fetchImpl(joinUrl(baseUrl, "/chat/completions"), {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (err) {
        clearTimeout(timer);
        throw new ProviderError(`LLM 服务请求失败: ${(err as Error)?.message ?? err}`);
      }
      clearTimeout(timer);

      const retryable = res.status === 429 || res.status >= 500;
      if (retryable && attempt <= maxRetries) {
        const header = Number(res.headers.get("retry-after"));
        // SEC-001：恶意/异常端点可给超大 Retry-After 挂死门禁——封顶 10 秒
        const backoff = Number.isFinite(header) && header > 0 ? Math.min(header * 1000, 10_000) : retryBaseMs * attempt;
        await sleep(backoff);
        continue;
      }
      if (!res.ok) {
        let detail = "";
        try {
          detail = (await res.text()).slice(0, 300);
        } catch {
          /* 读取错误体失败不影响主错误 */
        }
        throw new ProviderError(`LLM 服务返回错误状态 ${res.status}${detail ? `: ${detail}` : ""}`, res.status);
      }
      let data: {
        choices?: { message?: { content?: string; tool_calls?: { id?: string; function?: { name?: string; arguments?: string } }[] } }[];
        usage?: { total_tokens?: number };
      };
      try {
        data = await res.json();
      } catch {
        throw new ProviderError("LLM 服务返回非 JSON 响应", res.status);
      }
      const message = data.choices?.[0]?.message;
      const text = typeof message?.content === "string" ? message.content : "";
      const toolCalls = (message?.tool_calls ?? []).map((tc) => ({
        id: tc.id ?? "",
        name: tc.function?.name ?? "",
        args: safeParseArgs(tc.function?.arguments),
      }));
      if (!text && toolCalls.length === 0) {
        throw new ProviderError("LLM 服务响应缺少 message.content 或 tool_calls", res.status);
      }
      const tokens = typeof data.usage?.total_tokens === "number" ? data.usage.total_tokens : undefined;
      return { text, toolCalls, tokens };
    }
  }

  return { chat, model };
}

function safeParseArgs(raw?: string): Record<string, unknown> {
  if (typeof raw !== "string" || raw.length === 0) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** 脚本化 LLM：按序消耗脚本回复；耗尽后循环末条（确定性，本地/CI 零成本演示） */
export function createScriptedLlm(replies: string[]): Llm & { calls: number } {
  if (replies.length === 0) throw new Error("脚本回复不能为空");
  let calls = 0;
  return {
    get calls() {
      return calls;
    },
    async chat() {
      const text = replies[Math.min(calls, replies.length - 1)];
      calls += 1;
      return { text, tokens: 0 };
    },
  };
}

/** 限流包装：http provider 专用（脚本 LLM 本地零成本，不限流） */
export function withRateLimit(llm: Llm, limiter: TokenBucketLimiter, key = "regression"): Llm {
  return {
    async chat(messages, opts) {
      const r = limiter.check(key);
      if (!r.allowed) {
        throw new ProviderError(`限流：请 ${r.retryAfterSeconds}s 后重试（令牌桶 capacity=${limiter.capacity}/refill=${limiter.refillPerMinute} 每分钟）`);
      }
      return llm.chat(messages, opts);
    },
  };
}
