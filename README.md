# vehfuzz (skeleton)

Headless（无前端）车载协议 fuzzing 平台骨架：统一输入/输出工件目录，后续通过插件补齐真实接口与协议栈。

## Quickstart

在仓库根目录执行：

```bash
python fuzz/vehfuzz/scripts/vehfuzz.py --help
python fuzz/vehfuzz/scripts/vehfuzz.py plugins
python fuzz/vehfuzz/scripts/vehfuzz.py run --help
python fuzz/vehfuzz/scripts/vehfuzz.py run
```

默认读取 `fuzz/vehfuzz/configs/*.yaml` 并在 `fuzz/vehfuzz/runs/<run_id>/` 生成：

- `config/`：配置快照
- `manifest.json`：运行元数据
- `report.md`：Markdown 报告（骨架）

## Linux 仿真

参考：`fuzz/vehfuzz/docs/linux_sim.md`

## Integrations

参考：`fuzz/vehfuzz/docs/integrations.md`
