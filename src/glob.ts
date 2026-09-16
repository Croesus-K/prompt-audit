/**
 * 极简 glob 匹配（零依赖），仅服务于 .prompt-audit.json 的 allow 路径过滤。
 * 支持：** 跨目录段、* 单段内任意字符、? 单段内单个字符。
 * 语义：模式是整体锚定的，levels/** 不会命中 srclevels.md（可预测性优先）。
 */

/** 把不含元字符的字符转成正则安全文本 */
function escapeLiteral(ch: string): string {
  return /[\\^$.*+?()[\]{}|]/.test(ch) ? `\\${ch}` : ch;
}

/** 翻译 glob 主体为正则源码（不含锚点） */
function translate(pattern: string): string {
  let out = '';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        i++;
        if (pattern[i + 1] === '/') {
          i++;
          out += '(?:.*/)?'; // '**/' 匹配零层或多层目录
        } else {
          out += '.*';
        }
      } else {
        out += '[^/]*';
      }
    } else if (ch === '?') {
      out += '[^/]';
    } else {
      out += escapeLiteral(ch);
    }
  }
  return out;
}

/** 单个模式 → 整体锚定的正则；`dir/**` 额外兼容目录本身 */
function globToRegExp(pattern: string): RegExp {
  const normalized = pattern.replace(/\\/g, '/');
  const body =
    normalized.endsWith('/**') && normalized.length > 3
      ? translate(normalized.slice(0, -3)) + '(?:/.*)?'
      : translate(normalized);
  return new RegExp(`^${body}$`);
}

/** path 是否命中任一 glob 模式（路径分隔符统一按 / 处理） */
export function matchGlob(path: string, patterns: string[]): boolean {
  const normalized = path.replace(/\\/g, '/');
  return patterns.some((pattern) => globToRegExp(pattern).test(normalized));
}