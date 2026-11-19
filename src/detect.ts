/**
 * 公式注入检测引擎。对「解析后的单元格值」做判定。
 *
 * 判定顺序:
 *  1. 纯数字(含负数、小数、科学计数、千分位、百分号)→ 安全,永不转义。
 *     这是「不能把正常数字/负数改花」的底线。
 *  2. 剥掉前导空白(空格 \t \r \n 及全部 Unicode 空白)后,首字符命中
 *     某软件的触发字符 → 该软件下会被当公式解析。
 *  3. 原值不命中、但 NFKC 归一化后命中(全角 = + - @)→ 绕过型攻击。
 *  4. 以 `+` 开头的纯数字(典型是国际电话号码)→ 不会执行公式,但
 *     Excel 会把它强转成数字、丢掉 `+` 号,属于数据保真风险,单独分级。
 *
 * 输出每个命中了哪些软件、用了哪些绕过手法,供报告和加固使用。
 */

import { PROFILES, DANGEROUS_PATTERNS, DEFAULT_PROFILE_IDS } from "./rules.ts";

export type Severity = "critical" | "high" | "medium" | "safe";

export type EvasionTechnique =
  | "leading-whitespace" // 前导空白(空格/制表符/换行)藏触发字符
  | "fullwidth-trigger" // 全角触发符号绕过半角过滤
  | "leading-quote-char" // 已带 ' 文本标记(可能是手工绕过尝试)
  | "none";

export interface CellAnalysis {
  value: string;
  severity: Severity;
  /** 是否会被至少一个目标软件当公式解析 */
  isFormula: boolean;
  /** 命中的软件 id 列表 */
  matchedProfiles: string[];
  /** 命中的危险函数/协议特征 */
  dangerousPatterns: string[];
  evasion: EvasionTechnique[];
  /** 人类可读的判定原因 */
  reasons: string[];
}

const LEADING_WS_RE = /^\s+/u;

/** 纯数字:符号 + 整数/小数/千分位 + 可选科学计数 + 可选百分号。 */
const PLAIN_NUMBER_RE =
  /^[+-]?(\d{1,3}(,\d{3})+|\d+)(\.\d+)?([eE][+-]?\d+)?%?$/;

/** 以 + 开头的纯数字(国际电话号典型形态)。 */
const LEADING_PLUS_NUMBER_RE = /^\+\d[\d\s-]*\d$/;

export function isPlainNumber(value: string): boolean {
  return PLAIN_NUMBER_RE.test(value.trim());
}

function stripLeadingWhitespace(v: string): { stripped: string; hadWhitespace: boolean } {
  const m = v.match(LEADING_WS_RE);
  if (!m) return { stripped: v, hadWhitespace: false };
  return { stripped: v.slice(m[0].length), hadWhitespace: true };
}

function fullwidthNormalize(v: string): string {
  // NFKC 归一化:全角 = + - @ 以及全角字母(ＷＥＢＳＥＲＶＩＣＥ)一并归位
  return v.normalize("NFKC");
}

/** 检查某个(已按软件规则预处理过的)值的首字符是否触发该软件。 */
function firstCharTriggers(value: string, profileId: string): boolean {
  const profile = PROFILES[profileId];
  if (!profile) return false;
  const first = value[0];
  return first !== undefined && profile.triggers.has(first);
}

export function analyzeCell(
  value: string,
  profileIds: readonly string[] = DEFAULT_PROFILE_IDS,
): CellAnalysis {
  const result: CellAnalysis = {
    value,
    severity: "safe",
    isFormula: false,
    matchedProfiles: [],
    dangerousPatterns: [],
    evasion: [],
    reasons: [],
  };
  if (value === "") return result;

  // 1. 纯数字直接放行(含 "-123"、"+5"、"1,234.5"、"1e6"、"50%")
  if (isPlainNumber(value)) {
    // 但以 + 开头的数字在 Excel 里会被强转、丢符号 → 保真风险
    if (LEADING_PLUS_NUMBER_RE.test(value.trim())) {
      result.severity = "medium";
      result.reasons.push("以 + 开头的数字(疑似电话号码),Excel 会强转为数字并丢失 + 号");
    }
    return result;
  }

  const { stripped, hadWhitespace } = stripLeadingWhitespace(value);
  if (hadWhitespace) result.evasion.push("leading-whitespace");

  // 2. 半角触发(按各软件的前导空白处理规则分别判定)
  const matched = new Set<string>();
  for (const id of profileIds) {
    const profile = PROFILES[id];
    if (!profile) continue;
    const candidate = profile.trimsLeadingWhitespace ? stripped : value;
    if (firstCharTriggers(candidate, id)) matched.add(id);
  }

  // 3. 全角触发:原值没命中时,对全角归一化后的值再查一遍
  let fullwidthHit = false;
  if (matched.size === 0) {
    const normalized = fullwidthNormalize(stripped);
    if (normalized !== stripped) {
      for (const id of profileIds) {
        if (firstCharTriggers(normalized, id)) matched.add(id);
      }
      if (matched.size > 0) {
        fullwidthHit = true;
        result.evasion.push("fullwidth-trigger");
      }
    }
  }

  if (matched.size === 0) return result; // 安全

  result.isFormula = true;
  result.matchedProfiles = [...matched];

  // 4. 危险函数/协议特征 → critical,否则 high(原值与 NFKC 归一化值都查)
  const payload = stripped;
  const normalizedPayload = fullwidthNormalize(stripped);
  for (const { re, label } of DANGEROUS_PATTERNS) {
    if ((re.test(payload) || re.test(normalizedPayload)) && !result.dangerousPatterns.includes(label)) {
      result.dangerousPatterns.push(label);
    }
  }

  const names = result.matchedProfiles.map((id) => PROFILES[id]!.name).join("、");
  if (fullwidthHit) {
    result.reasons.push(`全角触发符号经归一化后在 ${names} 中会被当作公式`);
  } else {
    const lead = hadWhitespace ? "前导空白后的" : "";
    result.reasons.push(`${lead}首字符 "${stripped[0]}" 在 ${names} 中会触发公式解析`);
  }
  if (result.dangerousPatterns.length > 0) {
    result.severity = "critical";
    result.reasons.push(`命中危险特征:${result.dangerousPatterns.join("、")}`);
  } else {
    result.severity = "high";
  }
  return result;
}
