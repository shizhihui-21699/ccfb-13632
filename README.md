# csvsec — 导出安全检查与加固工具

防止「CSV/公式注入」(CSV Injection / Formula Injection):运营从后台导出表格,
用户在昵称等自由文本字段里填了 `=HYPERLINK(...)`、`=cmd|...` 这类内容,
表格软件一打开就执行公式,把相邻数据外发,甚至经 DDE 执行本机命令。

## 覆盖的软件规则

| 软件 | 触发字符 | 剥前导空白 | DDE |
|---|---|---|---|
| Microsoft Excel | `= + - @` | ✓ | ✓ |
| WPS 表格 | `= + - @` | ✓ | ✓ |
| LibreOffice Calc | `= + - @` | ✓ | ✓ |
| Google Sheets | `= + - @` | ✓ | ✗ |
| Apple Numbers | `=` | ✗ | ✗ |

加固取**所有软件的并集**:一份导出文件,在任何软件里打开都安全。
规则定义在 `src/rules.ts`,新软件加一条 profile 即可。

## 覆盖的绕过手法

- **前导空白**:空格、制表符、换行、全角空格(U+3000)等全部 Unicode 空白藏在触发字符前
- **全角符号**:`=` `+` `-` `@` 及全角函数名,经 NFKC 归一化后二次检测
- **引号嵌套**:检测作用在 RFC 4180 解析后的单元格**值**上,不做原始文本匹配
- **单元格内换行**:解析器正确处理引号字段内嵌换行,`\n=1+1` 无处遁形
- **危险载荷识别**:HYPERLINK / WEBSERVICE / IMPORTDATA / IMAGE / DDE / cmd| 等命中即升 critical

## 不误伤正常数据

- 纯数字(整数、负数、小数、科学计数、千分位、百分号)直接放行,永不转义
- `+8613800138000` 这类国际电话号不会执行公式,但 Excel 会吃掉 `+` 号 ——
  单独标 `medium` 并按文本转义保真(可用 `protectLeadingPlusNumber: false` 关闭)
- 等号/@不在开头、单引号开头的普通文本,一律原样

## 往返保真(修复后导回后台 = 原数据)

转义方案是前导单引号 `'`,配套互逆的 `escapeCell` / `restoreCell`:

```
needsEscape(v) = 危险(v) || (v 以 ' 开头 && needsEscape(v 去掉一个 '))
restore(escape(v)) === v   —— 对任意输入成立,包括用户本来就输了 '=xxx 的情况
```

**契约:后台导入通道必须用与导出时相同的 options 调 `restoreRows`,且只对本工具加固过的文件使用。**
`npm run cli -- verify-roundtrip <文件>` 可验证任意文件的往返一致性。

## 用法

```bash
npm test                 # 24 个测试:解析器/检测/往返不变量/批量扫描
npm run demo             # 示例后台:裸导出风险评估 → 加固 → 导回比对

# 批量扫描历史导出文件(退出码 0=干净 1=发现注入,可接 CI)
node src/cli.ts scan <文件或目录> [--json] [--include-medium] [--no-recursive]

# 加固单个文件
node src/cli.ts sanitize <文件> [-o 输出] [--in-place]

# 验证某文件 加固→还原 后逐值一致
node src/cli.ts verify-roundtrip <文件>
```

## 接入后台导出

```ts
import { parse, serialize } from "./src/csv.ts";
import { escapeRows, restoreRows } from "./src/sanitize.ts";

// 导出:rows 是 string[][]
const csv = serialize(escapeRows(rows).rows);

// 导入(回流):
const restored = restoreRows(parse(csvText).map(r => r.map(c => c.value)));
```

## 结构

```
src/csv.ts       RFC 4180 解析/序列化(引号、内嵌换行、TSV 嗅探)
src/rules.ts     各软件触发规则 + 危险函数特征库
src/detect.ts    单元格判定:严重度、命中软件、绕过手法
src/sanitize.ts  escape/restore 互逆对,往返保真的核心
src/scan.ts      目录批量扫描,输出结构化报告
src/cli.ts       命令行入口
demo/payloads.ts 攻击样本库(直接注入/绕过/正常数据三组)
demo/backend.ts  示例后台全链路演示
test/            node:test 测试,24 例
```

## 已知边界

- 仅处理 CSV/TSV 文本导出;.xlsx 是 zip+XML,公式在文件格式层另有存储方式,需单独适配
- `restore` 不能用于来源不明的文件(会把别人手工输入的合法 `'=xx` 剥掉一层)
- 全角字母拼出的危险函数名(如 `ＨＹＰＥＲＬＩＮＫ`)依赖 NFKC 归一化检测,已覆盖
