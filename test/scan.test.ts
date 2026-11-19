import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanPath } from "../src/scan.ts";
import { serialize } from "../src/csv.ts";

async function fixtureDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "csvsec-test-"));
  // 带毒文件 1:直接公式 + 前导空白绕过
  await writeFile(
    join(dir, "export-2024.csv"),
    serialize([
      ["id", "nick"],
      ["1", "=HYPERLINK(\"https://evil.example/\",\"x\")"],
      ["2", "  =1+1"],
      ["3", "张三"],
    ]),
  );
  // 带毒文件 2(子目录,TSV):全角等号
  await mkdir(join(dir, "nested"));
  await writeFile(join(dir, "nested", "export-2025.tsv"), "id\tnick\n4\t＝1+1\n");
  // 干净文件
  await writeFile(
    join(dir, "clean.csv"),
    serialize([
      ["id", "nick", "balance"],
      ["5", "李四", "-100"],
      ["6", "价格=100", "50%"],
    ]),
  );
  // 非表格文件不应被扫
  await writeFile(join(dir, "readme.md"), "=not scanned\n");
  return dir;
}

test("批量扫描:找出带毒文件,跳过干净文件和非表格文件", async () => {
  const dir = await fixtureDir();
  const report = await scanPath(dir);

  assert.equal(report.totalFiles, 3); // md 文件不计
  const bad1 = report.files.find((f) => f.file.endsWith("export-2024.csv"))!;
  const bad2 = report.files.find((f) => f.file.endsWith("export-2025.tsv"))!;
  const clean = report.files.find((f) => f.file.endsWith("clean.csv"))!;

  assert.equal(bad1.findings.length, 2);
  assert.equal(bad1.findings[0]!.severity, "critical"); // HYPERLINK
  assert.equal(bad1.findings[1]!.severity, "high"); // 前导空白
  assert.ok(bad1.findings[1]!.evasion.includes("leading-whitespace"));

  assert.equal(bad2.findings.length, 1);
  assert.ok(bad2.findings[0]!.evasion.includes("fullwidth-trigger"));

  assert.equal(clean.findings.length, 0);
  assert.ok(report.totalFindings >= 3);
});

test("扫描定位:行列号正确", async () => {
  const dir = await fixtureDir();
  const report = await scanPath(join(dir, "export-2024.csv"));
  const f = report.files[0]!;
  assert.equal(f.findings[0]!.row, 2); // 表头占第 1 行
  assert.equal(f.findings[0]!.col, 2); // nick 是第 2 列
});

test("单引号开头的历史导出(已加固过的)不会被误报为公式", async () => {
  const dir = await mkdtemp(join(tmpdir(), "csvsec-test-"));
  await writeFile(join(dir, "sanitized.csv"), "id,nick\n1,'=1+1\n");
  const report = await scanPath(dir);
  // '=1+1 在 Excel 里是文本标记,不会执行 → 不应报 isFormula 级发现
  const f = report.files[0]!;
  assert.equal(f.findings.filter((x) => x.severity === "critical" || x.severity === "high").length, 0);
});
