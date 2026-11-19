/**
 * 批量扫描:遍历目录中的 CSV/TSV 文件,找出带公式注入的单元格。
 * 用于排查历史导出文件里「已经带毒」的。
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join, extname } from "node:path";
import { parse, sniffDelimiter } from "./csv.ts";
import { analyzeCell, type CellAnalysis, type Severity } from "./detect.ts";
import { DEFAULT_PROFILE_IDS } from "./rules.ts";

export interface Finding {
  file: string;
  /** 1 起始的行号(按解析后的记录计,含表头) */
  row: number;
  /** 1 起始的列号 */
  col: number;
  value: string;
  severity: Severity;
  matchedProfiles: string[];
  dangerousPatterns: string[];
  evasion: string[];
  reasons: string[];
}

export interface FileScanResult {
  file: string;
  ok: boolean;
  error?: string;
  findings: Finding[];
  cellsScanned: number;
}

export interface ScanReport {
  files: FileScanResult[];
  totalFiles: number;
  totalFindings: number;
  bySeverity: Record<string, number>;
}

const SCANNABLE_EXTS = new Set([".csv", ".tsv", ".txt"]);

async function* walk(dir: string, recursive: boolean): AsyncGenerator<string> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (recursive) yield* walk(p, recursive);
    } else if (SCANNABLE_EXTS.has(extname(e.name).toLowerCase())) {
      yield p;
    }
  }
}

export interface ScanOptions {
  recursive?: boolean;
  profiles?: readonly string[];
  /** 是否把 medium(电话号码保真)也列入发现,默认 false,只报会执行的 */
  includeMedium?: boolean;
}

export async function scanFile(path: string, opts: ScanOptions = {}): Promise<FileScanResult> {
  const profiles = opts.profiles ?? DEFAULT_PROFILE_IDS;
  const includeMedium = opts.includeMedium ?? false;
  const findings: Finding[] = [];
  let cellsScanned = 0;

  try {
    const text = await readFile(path, "utf8");
    const delimiter = sniffDelimiter(text);
    const rows = parse(text, { delimiter });
    rows.forEach((row, r) => {
      row.forEach((cell, c) => {
        cellsScanned += 1;
        const a: CellAnalysis = analyzeCell(cell.value, profiles);
        if (a.severity === "safe") return;
        if (a.severity === "medium" && !includeMedium) return;
        findings.push({
          file: path,
          row: r + 1,
          col: c + 1,
          value: cell.value,
          severity: a.severity,
          matchedProfiles: a.matchedProfiles,
          dangerousPatterns: a.dangerousPatterns,
          evasion: a.evasion,
          reasons: a.reasons,
        });
      });
    });
    return { file: path, ok: true, findings, cellsScanned };
  } catch (err) {
    return {
      file: path,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      findings,
      cellsScanned,
    };
  }
}

export async function scanPath(target: string, opts: ScanOptions = {}): Promise<ScanReport> {
  const st = await stat(target);
  const files: string[] = [];
  if (st.isDirectory()) {
    for await (const f of walk(target, opts.recursive ?? true)) files.push(f);
  } else {
    files.push(target);
  }

  const report: ScanReport = {
    files: [],
    totalFiles: 0,
    totalFindings: 0,
    bySeverity: {},
  };
  for (const f of files.sort()) {
    const r = await scanFile(f, opts);
    report.files.push(r);
    report.totalFiles += 1;
    report.totalFindings += r.findings.length;
    for (const finding of r.findings) {
      report.bySeverity[finding.severity] = (report.bySeverity[finding.severity] ?? 0) + 1;
    }
  }
  return report;
}
