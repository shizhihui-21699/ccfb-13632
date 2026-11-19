import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeCell } from "../src/detect.ts";
import { needsEscape } from "../src/sanitize.ts";
import { PAYLOADS } from "../demo/payloads.ts";

test("样本库:每个样本的转义决策符合预期", () => {
  for (const p of PAYLOADS) {
    assert.equal(
      needsEscape(p.value),
      p.shouldEscape,
      `样本 ${p.id} (${JSON.stringify(p.value)}): 期望 shouldEscape=${p.shouldEscape}`,
    );
  }
});

test("直接公式:命中全部软件,危险函数升为 critical", () => {
  const a = analyzeCell('=HYPERLINK("https://evil.example/","x")');
  assert.equal(a.severity, "critical");
  assert.ok(a.matchedProfiles.includes("excel"));
  assert.ok(a.matchedProfiles.includes("google-sheets"));
  assert.ok(a.matchedProfiles.includes("numbers"));
  assert.ok(a.dangerousPatterns.some((l) => l.includes("HYPERLINK")));
});

test("前导空白绕过:空格/制表符/换行/全角空格", () => {
  for (const v of ["  =1+1", "\t=1+1", "\n=1+1", "　=1+1", " \t\r\n =1+1"]) {
    const a = analyzeCell(v);
    assert.ok(a.isFormula, JSON.stringify(v));
    assert.ok(a.evasion.includes("leading-whitespace"), JSON.stringify(v));
  }
});

test("全角符号绕过:= + @", () => {
  for (const v of ["＝1+1", "＋SUM(1,2)", "＠SUM(1,2)"]) {
    const a = analyzeCell(v);
    assert.ok(a.isFormula, JSON.stringify(v));
    assert.ok(a.evasion.includes("fullwidth-trigger"), JSON.stringify(v));
  }
});

test("正常数字/负数/百分数/千分位:安全且不转义", () => {
  for (const v of ["123", "-123", "-0.5", "1e6", "1,234.50", "50%", "+5"]) {
    const a = analyzeCell(v);
    assert.equal(a.severity, "safe", v);
    assert.ok(!needsEscape(v), v);
  }
});

test("电话号码 +86...:不判公式,但标 medium 保真风险", () => {
  const a = analyzeCell("+8613800138000");
  assert.equal(a.severity, "medium");
  assert.ok(!a.isFormula);
});

test("等号/特殊符号不在开头:安全", () => {
  for (const v of ["价格=100", "user@example.com", "a+b", "他说\"=1+1\""]) {
    assert.ok(!analyzeCell(v).isFormula, v);
  }
});

test("Numbers 只认等号:+SUM 不命中 numbers 但命中 excel", () => {
  const a = analyzeCell("+SUM(1,2)");
  assert.ok(a.matchedProfiles.includes("excel"));
  assert.ok(!a.matchedProfiles.includes("numbers"));
});
