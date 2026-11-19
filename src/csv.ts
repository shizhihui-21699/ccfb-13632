/**
 * RFC 4180 CSV/TSV 解析与序列化。
 *
 * 要点:
 * - 引号字段内可含分隔符、双引号("" 转义)、换行(CR/LF/CRLF)。
 * - 解析产出「单元格值」,公式检测必须作用在解析后的值上,
 *   而不是原始文本 —— 否则 `"=1+1`、引号嵌套、换行夹带都会绕过。
 * - 序列化按最小必要加引号,保证 parse(serialize(rows)) 与 rows 完全一致。
 */

export interface CsvOptions {
  /** 字段分隔符,默认 ",";TSV 传 "\t" */
  delimiter?: string;
}

export interface ParsedCell {
  value: string;
  /** 原始文件中该字段是否带引号(仅供诊断,不影响值) */
  quoted: boolean;
}

export type Row = ParsedCell[];

export class CsvParseError extends Error {
  readonly offset: number;
  constructor(message: string, offset: number) {
    super(`${message} (字节偏移 ${offset})`);
    this.name = "CsvParseError";
    this.offset = offset;
  }
}

/** 解析 CSV/TSV 文本为二维单元格数组。 */
export function parse(text: string, opts: CsvOptions = {}): Row[] {
  const delimiter = opts.delimiter ?? ",";
  if (delimiter.length !== 1) throw new Error("delimiter 必须是单字符");

  const rows: Row[] = [];
  let row: Row = [];
  let field = "";
  let quoted = false;
  let inQuotes = false;
  let fieldStart = true; // 当前位置是否处于字段开头(决定引号是否开启引号字段)
  let i = 0;
  const n = text.length;

  const pushField = () => {
    row.push({ value: field, quoted });
    field = "";
    quoted = false;
    fieldStart = true;
  };
  const pushRow = () => {
    pushField();
    rows.push(row);
    row = [];
  };

  while (i < n) {
    const ch = text[i]!;

    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      field += ch;
      i += 1;
      continue;
    }

    if (ch === '"' && fieldStart) {
      inQuotes = true;
      quoted = true;
      fieldStart = false;
      i += 1;
      continue;
    }
    if (ch === delimiter) {
      pushField();
      i += 1;
      continue;
    }
    if (ch === "\r") {
      // \r\n 或孤立 \r 都视为行结束
      if (text[i + 1] === "\n") i += 1;
      pushRow();
      i += 1;
      continue;
    }
    if (ch === "\n") {
      pushRow();
      i += 1;
      continue;
    }
    field += ch;
    fieldStart = false;
    i += 1;
  }

  if (inQuotes) {
    throw new CsvParseError("引号字段未闭合", n);
  }
  // 文件末尾无换行时收尾;若文本以换行结尾,最后一行为空则丢弃
  if (field.length > 0 || row.length > 0 || !fieldStart) {
    pushRow();
  }
  return rows;
}

/** 序列化为 CSV 文本。lineEnding 默认 CRLF(RFC 4180)。 */
export function serialize(
  rows: string[][],
  opts: CsvOptions & { lineEnding?: string } = {},
): string {
  const delimiter = opts.delimiter ?? ",";
  const eol = opts.lineEnding ?? "\r\n";
  return rows.map((r) => r.map((c) => escapeField(c, delimiter)).join(delimiter)).join(eol) + (rows.length ? eol : "");
}

function escapeField(value: string, delimiter: string): string {
  if (
    value.includes('"') ||
    value.includes(delimiter) ||
    value.includes("\n") ||
    value.includes("\r")
  ) {
    return '"' + value.replaceAll('"', '""') + '"';
  }
  return value;
}

/** 嗅探分隔符:首行里 tab 多于逗号则按 TSV 处理。 */
export function sniffDelimiter(text: string): string {
  const firstLine = text.split(/\r\n|\r|\n/, 1)[0] ?? "";
  const tabs = (firstLine.match(/\t/g) ?? []).length;
  const commas = (firstLine.match(/,/g) ?? []).length;
  return tabs > commas ? "\t" : ",";
}
