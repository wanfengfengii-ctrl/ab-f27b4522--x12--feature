# X12 信封审计 API

供应链集成平台在接收合作方 X12 批次前，对**信封层级**做结构审计，拒绝截断、拼接或
计数不符的报文，避免其进入后续结算。

- 纯 Python 3 标准库实现，无第三方依赖。
- 单个 `POST /api/x12/audit` 接口，接收 `application/octet-stream` 原始 ASCII 报文（≤ 2 MiB）。
- 可选 `?batch=interchanges`：同一正文承载 1..16 个**完整交换**，逐交换审计（见下文“批次模式”）。
- 从定长 ISA 段读取三个分隔符：
  - 元素分隔符：ISA 第 4 个字节（偏移 3）
  - 组件分隔符：ISA 第 105 个字节（偏移 104，即 ISA16）
  - 段终止符：ISA 第 106 个字节（偏移 105）

## 审计规则

- 全报文为 ASCII，长度 1..2 MiB，必须以且仅有一个 ISA 段开头。
- 唯一的 ISA/IEA 交换；报文结束后不得再出现任何段（防拼接）。
- 交换内含 1..64 个 GS/GE 功能组；每组内含 1..500 个 ST/SE 事务集。
- 层级不得交错（GS/ST/SE/GE/IEA 必须正确嵌套）。
- 成对控制号必须一致：ST02↔SE02、GS06↔GE02、ISA13↔IEA02。
- SE01 段数必须等于 ST 到 SE 的实际段数。
- GE01 事务数、IEA01 组数必须与实际计数吻合。
- 报文必须以段终止符结束（末段缺终止符视为截断）。

段按文档顺序处理，**内层信封错误先于任何外层汇总抛出**：即使 GE01、IEA01 同时
错误，较早的 SE 段数错误仍会先返回，不会被外层汇总掩盖。

## 接口

### `POST /api/x12/audit`

成功（200）：

```json
{
  "interchange_control_number": "000000001",
  "group_count": 2,
  "transaction_count": 3,
  "sha256": "f826db39…"
}
```

失败（信封类错误 422；空报文/非 ASCII 为 400；超过 2 MiB 为 413；
Content-Type 错误为 415）：

```json
{
  "error": {
    "code": "SEGMENT_COUNT_MISMATCH",
    "message": "SE01 declares 2 segments but the ST..SE envelope spans 3",
    "segment": 5
  }
}
```

`segment` 为首个可定位错误的 1 基段序号（ISA 为 1）。

### 批次模式 `POST /api/x12/audit?batch=interchanges`

省略该参数时上述契约完全不变。启用后，2 MiB 正文可包含 1..16 个完整交换：

- 每个交换的 ISA **独立声明**自己的三个分隔符（支持批内分隔符切换）；
- 交换之间仅允许出现 CR、LF 字节（零个或多个，可为空）；
- 同批 ISA13 交换控制号必须唯一；
- 各交换仍独立遵守组数（1..64）、事务数（≤500/组）、嵌套、配对与计数规则；
- 错误**不会**被前一交换的合法 IEA 结束掩盖：逐交换流式解析，遇到 IEA 即停，
  再从下一 ISA 起按其分隔符继续。

成功（200）按输入顺序返回各交换摘要，并给出合计与整批 SHA-256：

```json
{
  "interchanges": [
    {
      "interchange_control_number": "000000001",
      "group_count": 1,
      "transaction_count": 1,
      "sha256": "…"
    },
    {
      "interchange_control_number": "000000002",
      "group_count": 2,
      "transaction_count": 3,
      "sha256": "…"
    }
  ],
  "interchange_count": 2,
  "group_count": 3,
  "transaction_count": 4,
  "sha256": "<sha-256 of the whole batch body>"
}
```

失败（422 为主；体量/编码类沿用 400/413）时 `segment` 从**整批首段**起算，
并额外返回 1 基 `interchange` 序号：

```json
{
  "error": {
    "code": "SEGMENT_COUNT_MISMATCH",
    "message": "SE01 declares 2 segments but the ST..SE envelope spans 3",
    "segment": 11,
    "interchange": 2
  }
}
```

新增稳定错误码：

| code | 含义 |
|---|---|
| `INTERCHANGE_LIMIT_EXCEEDED` | 批次超过 16 个交换 |
| `DUPLICATE_CONTROL_NUMBER` | 同批两个交换的 ISA13 相同 |
| `INTERCHANGE_JUNK` | 交换之间（或整批末尾）出现 CR/LF 以外的字节 |
| `INVALID_BATCH_PARAMETER`（400） | `batch` 参数取值非 `interchanges` |

批次模式下其余信封错误码（`SEGMENT_COUNT_MISMATCH`、`MISSING_IEA` 等）保持不变，
但 `segment` 为全局段号、`interchange` 指向出错交换。

稳定错误码：

| code | 含义 |
|---|---|
| `EMPTY_MESSAGE` / `MESSAGE_TOO_LARGE` / `NON_ASCII` | 报文体量或编码问题 |
| `MISSING_ISA` / `ISA_TOO_SHORT` / `ISA_MALFORMED` / `BAD_DELIMITER` | ISA 定长结构或分隔符非法 |
| `MULTIPLE_INTERCHANGES` | 出现第二个 ISA（拼接报文） |
| `TRAILING_DATA` | IEA 之后还有数据 |
| `MISSING_TERMINATOR` / `EMPTY_SEGMENT` | 截断或空段 |
| `NESTING_VIOLATION` | 信封层级交错 |
| `GROUP_LIMIT_EXCEEDED` / `TRANSACTION_LIMIT_EXCEEDED` | 超出 64 组 / 每组 500 事务 |
| `ZERO_GROUPS` / `ZERO_TRANSACTIONS` | 组或事务为空 |
| `ST_MALFORMED` / `SE_MALFORMED` / `GE_MALFORMED` / `IEA_MALFORMED` / `GS_MALFORMED` | 信封段缺元素或计数非数字 |
| `SEGMENT_COUNT_MISMATCH` | SE01 与 ST..SE 实际段数不符 |
| `GE_COUNT_MISMATCH` / `IEA_COUNT_MISMATCH` | GE01/IEA01 计数不符 |
| `CONTROL_NUMBER_MISMATCH` | 成对控制号不一致 |
| `MISSING_SE` / `MISSING_GE` / `MISSING_IEA` | 报文截断、缺少闭合段 |
| `UNEXPECTED_SEGMENT` | 信封段之外的段出现在事务集外 |

### `GET /health`

返回 `{"status":"ok"}`，供 Docker / Compose 健康检查与 verify 服务等待就绪。

## 本地运行（无需 Docker）

```bash
python3 -m app.server                       # 默认 0.0.0.0:8080
PORT=9090 python3 -m app.server
python3 -m unittest discover -s tests       # 单元测试
```

## Docker / Docker Compose

```bash
# 宿主机端口可配置（默认 8080）
HOST_PORT=9090 docker compose up --build -d api

# 一次性验证服务：等待 api 健康后执行全部检查，以退出码汇总
docker compose run --rm verify
# 或在 CI 中：
docker compose up --build --abort-on-container-exit --exit-code-from verify verify
```

`verify` 服务依次执行：

1. 等待 `http://api:8080/health` 就绪；
2. 单元测试（unittest，67 个用例，含批次解析与错误定位）；
3. 应用构建检查（`compileall` 字节编译）；
4. HTTP 冒烟（有效报文 + 多种损坏信封 + 单交换兼容、异分隔符批次、
   重复控制号、第二交换损坏/截断等批次场景 + 传输层错误）。

退出码按位汇总：`1` 健康超时、`2` 单元测试失败、`4` 构建检查失败、`8` HTTP 冒烟失败；
`0` 表示全部通过。

## 手工调用

```bash
curl -sS --data-binary @sample.edi \
  -H 'Content-Type: application/octet-stream' \
  http://localhost:8080/api/x12/audit

# 批次：一个文件内连续交付多个交换（各自分隔符、CR/LF 分隔）
curl -sS --data-binary @batch.edi \
  -H 'Content-Type: application/octet-stream' \
  'http://localhost:8080/api/x12/audit?batch=interchanges'
```
