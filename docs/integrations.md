# Integrations

## boofuzz (optional engine)

vehfuzz 可以把一次 fuzzing 运行统一落盘到 `runs/<run_id>/`，其中 `campaign.engine: boofuzz` 会以子进程方式运行你指定的 boofuzz 脚本，并把 boofuzz CSV 日志转换写入 `artifacts/events.jsonl`。

**配置**

```yaml
campaign:
  engine: boofuzz
  protocol: doip   # 仅用于标签/报告展示
  boofuzz:
    script: path/to/your_boofuzz_profile.py
    args: ["--cases", 200]
    timeout_s: 120
    add_repo_boofuzz_to_pythonpath: true  # 默认 true：自动把仓库内的 fuzz/boofuzz 加进 PYTHONPATH
```

**脚本约定**

- runner 会注入这些环境变量：
  - `VEHFUZZ_RUN_ID`
  - `VEHFUZZ_RUN_DIR`
  - `VEHFUZZ_CONFIG_DIR`
  - `VEHFUZZ_ARTIFACTS_DIR`
  - `VEHFUZZ_BOOFUZZ_CSV`（建议你的脚本把 `FuzzLoggerCsv` 写到这个路径）
  - `VEHFUZZ_TARGET_JSON` / `VEHFUZZ_CAMPAIGN_JSON` / `VEHFUZZ_ORACLE_JSON`
- 若脚本未生成 `VEHFUZZ_BOOFUZZ_CSV`，vehfuzz 仍会保留 stdout/stderr，但事件统计会更少。

**产物**

- `artifacts/boofuzz.csv`（由脚本生成）
- `artifacts/boofuzz.stdout.log` / `artifacts/boofuzz.stderr.log`（vehfuzz 捕获）
- `artifacts/events.jsonl`（vehfuzz 解析 boofuzz.csv 生成）
- `artifacts/summary.json` / `report.md`

**示例**

- DoIP(TCP)：`fuzz/vehfuzz/docs/examples/boofuzz_doip`
- SOME/IP(UDP)：`fuzz/vehfuzz/docs/examples/boofuzz_someip_udp`

需要先启动对应的目标回环服务：

```bash
python fuzz/vehfuzz/scripts/targets/doip_server.py --port 13400
python fuzz/vehfuzz/scripts/targets/someip_server.py --port 30509
```

然后运行：

```bash
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/boofuzz_doip
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/boofuzz_someip_udp
```

## CANalyzat0r (seed import)

vehfuzz 支持把 CANalyzat0r 的 “Project Export” 文本文件解析成 CAN frame seeds：`seed.type: canalyzat0r_export`。

**配置**

```yaml
campaign:
  protocol: can
  seed:
    type: canalyzat0r_export
    path: your_export.txt
```

**示例**

- `fuzz/vehfuzz/docs/examples/can_canalyzat0r_export`

## cantools (DBC 信号级)

vehfuzz 的 `protocol: can_dbc` 使用 DBC 做信号级编码/变异（依赖 `cantools`，可选安装）。

安装依赖：

```bash
python -m pip install -r fuzz/vehfuzz/requirements-dbc.txt
```

示例：

- `fuzz/vehfuzz/docs/examples/can_dbc_vcan0`
