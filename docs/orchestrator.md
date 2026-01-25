# Orchestrator（多通道并行联动 / 事件触发）

`campaign.engine: orchestrator` 用于“多通道并行监听 + 事件触发联动”（你们说的综合工具、联动模式 B）。

核心点：
- 一次 run 内可以同时启多个 **channel**（每个 channel 独占 `Adapter+Protocol+Oracle`）
- channel 的 TX/RX/ERROR 会写入同一个 `artifacts/events.jsonl`
- 规则引擎消费 RX/TX/ERROR 事件，命中后触发动作（发包 / 写上下文 / 停止）

## 最小配置结构

```yaml
campaign:
  engine: orchestrator
  duration_s: 10
  channels:
    - id: can
      protocol: can
      target:
        adapter: { type: socketcan, channel: vcan0 }
      seed:
        type: inline_hex
        values: ["02010d"]
      generator:
        type: none

    - id: doip
      protocol: uds
      target:
        adapter: { type: doip, host: 127.0.0.1, port: 13400, routing_activation: true }
      seed:
        type: inline_hex
        values: [""]

  rules:
    - id: can_triggers_doip
      cooldown_s: 0.2
      when:
        channel_id: can
        event: rx
        fields:
          inner_uds:
            kind: negative_response
      then:
        - action: send
          channel_id: doip
          mutated_hex: "02f190"
```

## channel 配置说明（常用字段）

- `id`：通道唯一 ID（字符串）
- `protocol` / `protocol_config`：协议插件及其配置
- `target.adapter`：适配器插件及其配置
- `seed`：种子配置（支持 `inline_hex`/`candump`/`pcap` 等）
- `generator`（可选）：
  - `type: fuzz`：该通道主动发包（按 seeds 变异）
  - `type: none`：该通道只收包/响应联动
- `queue_maxsize`（可选）：该通道动作队列上限（防止事件风暴堆积）

## 规则配置说明

每条规则包含：
- `id`：规则 ID
- `cooldown_s`（可选）：命中后冷却时间，防止风暴重复触发
- `max_matches`（可选）：最多命中次数（到达后不再触发）
- `when`：匹配条件
- `then`：动作列表

### when 支持的匹配方式

1) 顶层筛选：
- `channel_id`: 触发通道
- `event`: `rx`/`tx`/`error`
- `protocol`: 触发通道的 protocol 名称

2) 结构化字段子集匹配（推荐给小白，最直观）：
- `fields`: 会与 `parsed.fields` 做“子集匹配”

3) path 匹配（更灵活）：
- `match`: 列表，每项 `{path, op, value}`
  - `path`：如 `parsed.fields.inner_uds.nrc`、`meta.doip.src`、`parsed.fields.entries.0.type_name`
  - `op`：`exists/not_exists/eq/ne/gt/gte/lt/lte/contains/in`
  - `value`：期望值（`exists` 不需要）

### then 支持的动作

- `set_context`
  - `key`: 写入的 key
  - `value`: 固定值
  - `value_from`: 从触发事件取值（dot path）

- `send`
  - `channel_id`: 目标通道
  - `mutated_hex`: 直接指定 payload（hex）
  - `mutated_from_event`: 从触发事件取 hex/bytes
  - `mutated_from_context`: 从 context 取 hex/bytes
  - `seed_index`: 选用哪个 seed（默认 0）
  - `meta_overrides`: 固定 meta 覆盖
  - `meta_overrides_from_event`: `{k: "path.to.value"}`
  - `meta_overrides_from_context`: `{k: "context_key"}`

- `stop`
  - `reason`: 写入日志并停止整个 orchestrator

## 输出与复现

运行输出目录：`runs/<run_id>/`
- 事件流：`artifacts/events.jsonl`
- 汇总：`artifacts/summary.json`（包含 `rules_detail.matches/suppressed`）

