/**
 * 各表格软件的公式触发规则。
 *
 * 同一个单元格在不同软件里是否会被当成公式执行,规则并不一致:
 * - Excel / WPS:`=` `+` `-` `@` 开头都会进入公式解析;解析前会剥掉前导
 *   空格和制表符,所以 "  =1+1"、"\t=cmd|..." 照样执行;支持 DDE。
 * - LibreOffice Calc:触发字符同上,导入对话框默认会Trim前导空白。
 * - Google Sheets:触发字符同上;粘贴/导入时按 Trim 后的内容判断。
 * - Apple Numbers:只有 `=` 开头会进入公式编辑器。
 *
 * 攻击者还会用全角符号(= + - @)绕过只查半角的过滤器,
 * 某些下游管道会做 NFKC 归一化,归一化后同样成立 —— 因此检测时对
 * 原值和 NFKC 归一化值各查一遍。
 *
 * 加固策略取所有软件的并集:一份文件,处处安全。
 */

export interface SoftwareProfile {
  id: string;
  name: string;
  /** 半角触发字符(作用于剥掉前导空白之后的首字符) */
  triggers: ReadonlySet<string>;
  /** 该软件在判断前是否会剥掉前导空白(空格/制表符/换行等) */
  trimsLeadingWhitespace: boolean;
  /** 是否支持 DDE 一类的外部命令通道(影响危险函数清单的严重度) */
  hasDde: boolean;
}

export const PROFILES: Record<string, SoftwareProfile> = {
  excel: {
    id: "excel",
    name: "Microsoft Excel",
    triggers: new Set(["=", "+", "-", "@"]),
    trimsLeadingWhitespace: true,
    hasDde: true,
  },
  wps: {
    id: "wps",
    name: "WPS 表格",
    triggers: new Set(["=", "+", "-", "@"]),
    trimsLeadingWhitespace: true,
    hasDde: true,
  },
  libreoffice: {
    id: "libreoffice",
    name: "LibreOffice Calc",
    triggers: new Set(["=", "+", "-", "@"]),
    trimsLeadingWhitespace: true,
    hasDde: true,
  },
  "google-sheets": {
    id: "google-sheets",
    name: "Google Sheets",
    triggers: new Set(["=", "+", "-", "@"]),
    trimsLeadingWhitespace: true,
    hasDde: false,
  },
  numbers: {
    id: "numbers",
    name: "Apple Numbers",
    triggers: new Set(["="]),
    trimsLeadingWhitespace: false,
    hasDde: false,
  },
};

export const DEFAULT_PROFILE_IDS = Object.keys(PROFILES);

/** 全角 → 半角 的触发字符映射(NFKC 的子集,显式列出便于审计)。 */
export const FULLWIDTH_TRIGGERS: Record<string, string> = {
  "=": "=",
  "+": "+",
  "-": "-",
  "@": "@",
};

/**
 * 危险公式函数/协议关键字。命中这些的公式从「会被执行」升级为
 * 「明确恶意特征」(数据外发、命令执行)。
 */
export const DANGEROUS_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\bHYPERLINK\s*\(/i, label: "HYPERLINK 数据外发" },
  { re: /\bWEBSERVICE\s*\(/i, label: "WEBSERVICE 远程请求" },
  { re: /\bIMPORTDATA\s*\(/i, label: "IMPORTDATA 远程导入" },
  { re: /\bIMPORTXML\s*\(/i, label: "IMPORTXML 远程导入" },
  { re: /\bIMPORTFEED\s*\(/i, label: "IMPORTFEED 远程导入" },
  { re: /\bIMAGE\s*\(/i, label: "IMAGE 远程图片(可夹带参数)" },
  { re: /\bDDE\s*\(/i, label: "DDE 动态数据交换" },
  { re: /\b(cmd|powershell|bash|sh)\s*[|!]/i, label: "DDE 命令行通道" },
  { re: /^\s*=\s*cmd\s*\|/i, label: "DDE 命令行通道" },
  { re: /\bREGISTER\s*\(/i, label: "REGISTER 调用外部 DLL" },
];
