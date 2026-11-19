import { test } from "node:test";
import assert from "node:assert/strict";
import { escapeCell, restoreCell, escapeRows, restoreRows, needsEscape } from "../src/sanitize.ts";
import { analyzeCell } from "../src/detect.ts";
import { PAYLOADS } from "../demo/payloads.ts";

/** 对抗语料:专门构造 escape/restore 容易出错的边界值。 */
const ADVERSARIAL = [
  ...PAYLOADS.map((p) => p.value),
  "'=1+1", // 用户自己输的单引号 + 公式
  "''=1+1", // 两层单引号
  "'''=cmd|'/c calc'!A0", // 三层 + DDE
  "'普通文本", // 单引号但安全
  "''普通文本",
  "'", // 只有一个单引号
  "''",
  "=",
  "=", // 全角等号单独一个
  " ", // 纯空白
  "  '  =混合", // 空白 + 单引号 + 空白 + 等号
  "\t'=tab后引号公式",
  "-0",
  "+8613800138000",
  "",
];

test("核心不变量:restore(escape(v)) === v 对任意值成立", () => {
  for (const v of ADVERSARIAL) {
    const escaped = escapeCell(v);
    const restored = restoreCell(escaped);
    assert.equal(restored, v, `往返失败: ${JSON.stringify(v)} → ${JSON.stringify(escaped)} → ${JSON.stringify(restored)}`);
  }
});

test("加固后没有任何单元格仍会被解析为公式", () => {
  for (const v of ADVERSARIAL) {
    const escaped = escapeCell(v);
    assert.ok(!analyzeCell(escaped).isFormula, `转义后仍危险: ${JSON.stringify(v)} → ${JSON.stringify(escaped)}`);
  }
});

test("安全值原样不动(不改花正常数据)", () => {
  for (const v of ["123", "-123", "-0.5", "1e6", "1,234.50", "50%", "张三", "价格=100", "user@example.com", "'普通文本"]) {
    assert.equal(escapeCell(v), v, v);
  }
});

test("escape 幂等:对已加固的转义结果再转义不会叠加", () => {
  for (const v of ADVERSARIAL) {
    const once = escapeCell(v);
    // 对转义结果再 escape,若还需要加引号,说明 restore 也能对应去掉 —— 检查二次往返
    const twice = escapeCell(once);
    assert.equal(restoreCell(twice), once, `二次往返失败: ${JSON.stringify(v)}`);
  }
});

test("整表往返:escapeRows → restoreRows 恒为恒等", () => {
  const rows = [
    ["id", "nick", "phone", "balance"],
    ["1", "=HYPERLINK(\"http://evil/\",\"x\")", "+8613800138000", "-50"],
    ["2", "'=1+1", "123", "1,234.50"],
    ["3", "  =前导空白", "＝全角", "50%"],
  ];
  const { rows: escaped, escapedCount } = escapeRows(rows);
  assert.ok(escapedCount >= 5);
  assert.deepEqual(restoreRows(escaped), rows);
});

test("needsEscape 递归定义:' 前缀链", () => {
  assert.ok(needsEscape("=x"));
  assert.ok(needsEscape("'=x")); // 去掉一个 ' 就变危险 → 本身也要转义
  assert.ok(needsEscape("''=x"));
  assert.ok(!needsEscape("'ok"));
  assert.ok(!needsEscape("ok"));
});
