/**
 * 加固(转义)与还原。
 *
 * 转义方案:在危险值前加一个单引号 `'`。Excel/WPS/Sheets 都把前导
 * 单引号当作「按文本显示」标记,单元格显示内容与原值一致,公式不会执行。
 *
 * 「修复后再导回后台必须和原数据完全一致」由 escape/restore 这对
 * 互逆函数保证,关键在边界情况:用户数据本身就可能以 `'` 开头。
 * 规则定义(两边必须使用同一组 options):
 *
 *   needsEscape(v) = isDangerous(v)
 *                 || (v 以 ' 开头 && needsEscape(v 去掉首个 '))
 *   escape(v)      = needsEscape(v) ? "'" + v : v
 *   restore(v)     = (v 以 ' 开头 && needsEscape(v 去掉首个 ')) ? v 去掉首个 ' : v
 *
 * 即:凡是「去掉一个 ' 就会变得危险」的值,本身也要再补一个 '。
 * 这样 restore(escape(v)) === v 对任意输入成立(测试里有对抗语料验证),
 * 包括 `'=x`、`''=x` 这类本来就带单引号的昵称。
 *
 * 注意:restore 只能用于「确定经过 escape 的文件」的回流通道(后台导入),
 * 不要对来源不明的文件做 restore。
 */

import { analyzeCell, type Severity } from "./detect.ts";
import { DEFAULT_PROFILE_IDS } from "./rules.ts";

export interface SanitizeOptions {
  /** 目标软件,默认全部(并集,最保守) */
  profiles?: readonly string[];
  /**
   * 是否也转义「以 + 开头的纯数字」(电话号码保真),默认 true。
   * 关掉后 +8613800138000 这类值原样输出,Excel 打开会丢 + 号。
   */
  protectLeadingPlusNumber?: boolean;
}

const ESCAPED_SEVERITIES: Severity[] = ["high", "critical"];

function resolved(opts: SanitizeOptions) {
  return {
    profiles: opts.profiles ?? DEFAULT_PROFILE_IDS,
    protectLeadingPlusNumber: opts.protectLeadingPlusNumber ?? true,
  };
}

export function needsEscape(value: string, opts: SanitizeOptions = {}): boolean {
  const o = resolved(opts);
  if (isDangerous(value, o)) return true;
  if (value.startsWith("'")) return needsEscape(value.slice(1), opts);
  return false;
}

function isDangerous(value: string, o: Required<SanitizeOptions>): boolean {
  const a = analyzeCell(value, o.profiles);
  if (ESCAPED_SEVERITIES.includes(a.severity)) return true;
  if (a.severity === "medium" && o.protectLeadingPlusNumber) return true;
  return false;
}

/** 转义单个单元格。 */
export function escapeCell(value: string, opts: SanitizeOptions = {}): string {
  return needsEscape(value, opts) ? "'" + value : value;
}

/** 还原单个单元格(仅用于后台导入通道,options 必须与导出时一致)。 */
export function restoreCell(value: string, opts: SanitizeOptions = {}): string {
  if (value.startsWith("'") && needsEscape(value.slice(1), opts)) {
    return value.slice(1);
  }
  return value;
}

export interface SanitizeResult {
  rows: string[][];
  /** 被改动的单元格数 */
  escapedCount: number;
}

/** 转义整张表。 */
export function escapeRows(rows: string[][], opts: SanitizeOptions = {}): SanitizeResult {
  let escapedCount = 0;
  const out = rows.map((row) =>
    row.map((cell) => {
      const escaped = escapeCell(cell, opts);
      if (escaped !== cell) escapedCount += 1;
      return escaped;
    }),
  );
  return { rows: out, escapedCount };
}

/** 还原整张表。 */
export function restoreRows(rows: string[][], opts: SanitizeOptions = {}): string[][] {
  return rows.map((row) => row.map((cell) => restoreCell(cell, opts)));
}
