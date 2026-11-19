#!/usr/bin/env node
/**
 * csvsec CLI
 *
 *   node src/cli.ts scan <文件或目录> [--json] [--include-medium] [--no-recursive]
 *   node src/cli.ts sanitize <文件> [-o 输出文件] [--in-place]
 *   node src/cli.ts verify-roundtrip <文件>   验证 加固→还原 后与原文逐值一致
 *
 * scan 退出码: 0 = 干净, 1 = 发现注入, 2 = 用法/读取错误(可接 CI)。
 */

import { readFile, writeFile } from "node:fs/promises";
import { parse, serialize, sniffDelimiter } from "./csv.ts";
import { escapeRows, restoreRows } from "./sanitize.ts";
import { scanPath, type ScanReport } from "./scan.ts";

interface CliArgs {
  _: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): CliArgs {
  const _: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq >= 0) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else if (a.startsWith("--no-")) flags[a.slice(5)] = false;
      else flags[a.slice(2)] = true;
    } else if (a === "-o") {
      flags["o"] = argv[++i] ?? "";
    } else {
      _.push(a);
    }
  }
  return { _, flags };
}

function severityIcon(s: string): string {
  return s === "critical" ? "🔴" : s === "high" ? "🟠" : s === "medium" ? "🟡" : "⚪";
}

function printReport(report: ScanReport): void {
  for (const f of report.files) {
    if (!f.ok) {
      console.error(`✗ ${f.file}: ${f.error}`);
      continue;
    }
    if (f.findings.length === 0) continue;
    console.log(`\n${f.file} (${f.findings.length} 处)`);
    for (const x of f.findings) {
      console.log(`  ${severityIcon(x.severity)} [${x.severity}] R${x.row}C${x.col} ${JSON.stringify(truncate(x.value, 60))}`);
      for (const reason of x.reasons) console.log(`     ${reason}`);
      if (x.evasion.length > 0) console.log(`     绕过手法: ${x.evasion.join(", ")}`);
    }
  }
  console.log(
    `\n扫描 ${report.totalFiles} 个文件,共 ${report.totalFindings} 处发现` +
      (report.totalFindings
        ? ` (${Object.entries(report.bySeverity).map(([k, v]) => `${k}:${v}`).join(" ")})`
        : ",全部干净"),
  );
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

async function main(): Promise<number> {
  const { _, flags } = parseArgs(process.argv.slice(2));
  const cmd = _[0];
  const target = _[1];

  if (!cmd || (cmd !== "scan" && cmd !== "sanitize" && cmd !== "verify-roundtrip") || !target) {
    console.error(`用法:
  csvsec scan <文件|目录> [--json] [--include-medium] [--no-recursive]
  csvsec sanitize <文件> [-o 输出] [--in-place]
  csvsec verify-roundtrip <文件>`);
    return 2;
  }

  if (cmd === "scan") {
    const report = await scanPath(target, {
      recursive: flags["recursive"] !== false,
      includeMedium: flags["include-medium"] === true,
    });
    if (flags["json"]) console.log(JSON.stringify(report, null, 2));
    else printReport(report);
    if (report.files.some((f) => !f.ok)) return 2;
    return report.totalFindings > 0 ? 1 : 0;
  }

  const text = await readFile(target, "utf8");
  const delimiter = sniffDelimiter(text);
  const rows = parse(text, { delimiter }).map((r) => r.map((c) => c.value));

  if (cmd === "sanitize") {
    const { rows: safeRows, escapedCount } = escapeRows(rows);
    const out = serialize(safeRows, { delimiter });
    const outPath = flags["in-place"] ? target : typeof flags["o"] === "string" && flags["o"] ? flags["o"] : target.replace(/(\.[^.]+)?$/, ".safe$1");
    await writeFile(outPath, out, "utf8");
    console.log(`已加固 ${escapedCount} 个单元格 → ${outPath}`);
    return 0;
  }

  // verify-roundtrip
  const { rows: safeRows } = escapeRows(rows);
  const restored = restoreRows(safeRows);
  let mismatches = 0;
  for (let r = 0; r < rows.length; r++) {
    for (let c = 0; c < rows[r]!.length; c++) {
      if (restored[r]?.[c] !== rows[r]![c]) {
        mismatches++;
        console.error(`不一致 R${r + 1}C${c + 1}: 原=${JSON.stringify(rows[r]![c])} 回=${JSON.stringify(restored[r]?.[c])}`);
      }
    }
  }
  console.log(mismatches === 0 ? "往返一致 ✔" : `${mismatches} 处不一致 ✗`);
  return mismatches === 0 ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(2);
  },
);
