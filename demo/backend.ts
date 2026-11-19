/**
 * 示例后台:内存「数据库」→ 导出 CSV → 加固 → 再导回,验证全链路。
 *
 * 运行: npm run demo
 *
 * 演示三件事:
 *  1. 裸导出(不做防护)的 CSV 里有多少会被表格软件当公式执行;
 *  2. 加固导出后,扫描结果清零,且正常数字/负数/电话号没被改花;
 *  3. 加固文件经 restore 通道导回后台,与库中原始数据逐字节一致。
 */

import { serialize, parse } from "../src/csv.ts";
import { escapeRows, restoreRows } from "../src/sanitize.ts";
import { analyzeCell } from "../src/detect.ts";
import { PAYLOADS } from "./payloads.ts";

interface UserRow {
  id: number;
  nickname: string;
  phone: string;
  balance: string;
  note: string;
}

/** 造一批「用户自己填的」数据,昵称和备注里混进攻击样本。 */
function seedDatabase(): UserRow[] {
  const rows: UserRow[] = [
    { id: 1, nickname: "张三", phone: "+8613800138000", balance: "1234.50", note: "老客户" },
    { id: 2, nickname: "李四", phone: "+8613900139000", balance: "-50", note: "欠费待缴" },
  ];
  let id = 3;
  for (const p of PAYLOADS) {
    rows.push({
      id: id++,
      nickname: p.value,
      phone: "+8613700137000",
      balance: "100",
      note: `样本:${p.id}`,
    });
  }
  return rows;
}

const HEADERS = ["id", "nickname", "phone", "balance", "note"];

function toRows(db: UserRow[]): string[][] {
  return [
    HEADERS,
    ...db.map((u) => [String(u.id), u.nickname, u.phone, u.balance, u.note]),
  ];
}

/** 后台导出(加固版)。 */
function exportCsv(db: UserRow[]): string {
  const { rows, escapedCount } = escapeRows(toRows(db));
  console.log(`[导出] 加固转义了 ${escapedCount} 个单元格`);
  return serialize(rows);
}

/** 后台导入(restore 通道,options 必须与导出一致 —— 这里都用默认值)。 */
function importCsv(csvText: string): string[][] {
  const parsed = parse(csvText);
  return restoreRows(parsed.map((row) => row.map((c) => c.value)));
}

// ---------- 演示 ----------

const db = seedDatabase();
const originalRows = toRows(db);

console.log("=== 1. 裸导出(不加固)的风险评估 ===");
const rawCsv = serialize(originalRows);
const rawParsed = parse(rawCsv);
let dangerous = 0;
for (const [r, row] of rawParsed.entries()) {
  for (const [c, cell] of row.entries()) {
    const a = analyzeCell(cell.value);
    if (a.isFormula) {
      dangerous++;
      const loc = `R${r + 1}C${c + 1}`;
      console.log(`  [${a.severity}] ${loc} ${JSON.stringify(cell.value.slice(0, 60))}`);
      console.log(`         → ${a.reasons.join(";")}`);
    }
  }
}
console.log(`裸导出共 ${dangerous} 个单元格会被当公式解析\n`);

console.log("=== 2. 加固导出 ===");
const safeCsv = exportCsv(db);
const safeParsed = parse(safeCsv);
let remaining = 0;
for (const row of safeParsed) {
  for (const cell of row) {
    if (analyzeCell(cell.value).isFormula) remaining++;
  }
}
console.log(`加固后仍会被解析为公式的单元格: ${remaining}\n`);

console.log("=== 3. 加固文件导回后台,与原始数据比对 ===");
const imported = importCsv(safeCsv);
let mismatches = 0;
for (let r = 0; r < originalRows.length; r++) {
  for (let c = 0; c < originalRows[r]!.length; c++) {
    if (imported[r]?.[c] !== originalRows[r]![c]) {
      mismatches++;
      console.log(
        `  不一致 R${r + 1}C${c + 1}: 原=${JSON.stringify(originalRows[r]![c])} 回=${JSON.stringify(imported[r]?.[c])}`,
      );
    }
  }
}
console.log(mismatches === 0 ? "全部一致 ✔ 往返保真" : `发现 ${mismatches} 处不一致 ✗`);

console.log("\n=== 4. 正常数据抽查(不能被改花) ===");
for (const probe of ["-50", "1234.50", "+8613800138000", "张三"]) {
  const a = analyzeCell(probe);
  console.log(`  ${JSON.stringify(probe)} → severity=${a.severity}${a.reasons.length ? " (" + a.reasons[0] + ")" : ""}`);
}
