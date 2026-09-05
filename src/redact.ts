/**
 * 共享的脱敏模式：flag 形状受控令牌。
 * InjectArena 导出端点（攻 → 审）与本工具的 --export-corpus（审 → 攻）
 * 使用同一约定：FLAG{…} → FLAG{REDACTED}，其余明文保留。
 */
export const SECRET_FLAG_RE = /FLAG\{[^}\s]{0,64}\}/g;
