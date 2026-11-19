import { test } from "node:test";
import assert from "node:assert/strict";
import { parse, serialize, sniffDelimiter } from "../src/csv.ts";

test("基础解析", () => {
  const rows = parse("a,b,c\r\n1,2,3\r\n");
  assert.deepEqual(rows.map((r) => r.map((c) => c.value)), [
    ["a", "b", "c"],
    ["1", "2", "3"],
  ]);
});

test("引号字段:内嵌逗号、双引号、换行", () => {
  const text = 'name,note\r\n"张,三","他说""你好\n"\r\n';
  const rows = parse(text);
  assert.equal(rows[1]![0]!.value, "张,三");
  assert.equal(rows[1]![1]!.value, '他说"你好\n');
});

test("引号嵌套的公式载荷被正确解析出值", () => {
  // 攻击者把值写成 "=1+1,CSV 序列化后是 """=1+1"
  const rows = parse('id,nick\r\n1,"""=1+1"\r\n');
  assert.equal(rows[1]![1]!.value, '"=1+1');
});

test("序列化→解析 往返一致(含换行/引号/逗号/制表符)", () => {
  const data = [
    ["a", "b,c", 'd"e', "x\ny", "\t=cmd|'/c calc'!A0", ""],
    ["普通", "＝1+1", "  =空格", "'=引号", "-123", "+8613800138000"],
  ];
  const round = parse(serialize(data)).map((r) => r.map((c) => c.value));
  assert.deepEqual(round, data);
});

test("TSV 解析与嗅探", () => {
  const text = "a\tb\tc\n1\t2\t3\n";
  assert.equal(sniffDelimiter(text), "\t");
  const rows = parse(text, { delimiter: sniffDelimiter(text) });
  assert.equal(rows[1]![2]!.value, "3");
});

test("未闭合引号报错", () => {
  assert.throws(() => parse('a,"b\n1,2'), /未闭合/);
});

test("空字段与空行", () => {
  const rows = parse("a,,c\n,,\n");
  assert.deepEqual(rows.map((r) => r.map((c) => c.value)), [
    ["a", "", "c"],
    ["", "", ""],
  ]);
});
