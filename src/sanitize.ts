/**
 * 输出净化（SEC-001 自查引入）：
 * 扫描对象是**不受信仓库**——AI 资产里的文本会原样流进告警 evidence/message，
 * 再流进三个高危渲染面：
 *  1. PR 粘性评论（Markdown 表格/HTML 折叠块）→ 注入可伪造维护者通知、嵌跟踪图床
 *  2. GitHub Actions 工作流命令（::error / ::warning）→ 换行即可伪造标注
 *  3. CI 日志 → ANSI 控制序列
 * 三个净化函数按渲染面分别收口；机器可读输出（--json）不做净化，保持原样。
 */

/** 控制字符（含 \r \n \t 与 ANSI 序列的 ESC）→ 空格 */
export function stripControlChars(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f]/g, " ");
}

/** Markdown 表格单元格 / 评论正文安全：控制字符折叠 + 表格分隔符与尖括号转义 */
export function mdCell(s: string, maxLength = 200): string {
  return stripControlChars(s)
    .replace(/\|/g, "\\|")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/`/g, "'")
    .slice(0, maxLength);
}

/** 工作流命令 / 单行日志安全：控制字符折叠 + 截断 */
export function logLine(s: string, maxLength = 200): string {
  return stripControlChars(s).slice(0, maxLength);
}
