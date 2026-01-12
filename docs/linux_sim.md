# Linux 仿真快速验证

目标：在 Ubuntu 22.04 上用虚拟接口/回环服务，把 CAN / SOME-IP / DoIP / GNSS / Wi-Fi(PCAP) / Bluetooth(PCAP) 的链路跑通。

## 1) 基础

进入仓库根目录，确认 CLI 可用：

（建议先装依赖）

```bash
python -m pip install -r fuzz/vehfuzz/requirements.txt
```

然后：

```bash
python fuzz/vehfuzz/scripts/vehfuzz.py plugins
```

## 2) CAN（vcan0）

创建 vcan0：

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

启动 UDS ECU（ISO-TP over CAN，是真实诊断协议语义）：

```bash
python fuzz/vehfuzz/scripts/targets/uds_isotp_ecu.py --channel vcan0 --req-id 0x7E0 --resp-id 0x7E8
```

运行 UDS over ISO-TP 示例：

```bash
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/uds_isotp_vcan0
```

J1939 示例（同样跑在 vcan0 上）：

```bash
python fuzz/vehfuzz/scripts/targets/j1939_node.py --channel vcan0 --respond
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/j1939_vcan0
```

DBC 信号级示例（需要安装 cantools）：

```bash
python -m pip install -r fuzz/vehfuzz/requirements-dbc.txt
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/can_dbc_vcan0
```

## 3) SOME/IP（UDP）

启动 SOME/IP 服务端（按 SOME/IP 头解析并返回 Response）：

```bash
python fuzz/vehfuzz/scripts/targets/someip_server.py --port 30509
```

运行 SOME/IP 示例：

```bash
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/someip_udp_echo
```

SOME/IP Service Discovery（SD）示例：

```bash
python fuzz/vehfuzz/scripts/targets/someip_sd_server.py --port 30490
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/someip_sd_udp
```

## 4) DoIP（TCP）

启动 DoIP 目标端（含 Routing Activation + 诊断消息处理）：

```bash
python fuzz/vehfuzz/scripts/targets/doip_server.py --port 13400
```

运行 DoIP+UDS 示例：

```bash
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/doip_uds_tcp
```

## 5) GNSS（NMEA over UDP）

启动 NMEA 接收端：

```bash
python fuzz/vehfuzz/scripts/targets/nmea_udp_sink.py --port 30511
```

运行 GNSS 示例（会自动重算 NMEA checksum）：

```bash
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/gnss_nmea_udp
```

## 6) Wi-Fi / Bluetooth（PCAP 离线）

先生成一个最小 pcap（Ethernet linktype，仅用于演示离线管线）：

```bash
python fuzz/vehfuzz/scripts/gen_sample_pcap.py --out fuzz/vehfuzz/samples/sample_eth.pcap
python fuzz/vehfuzz/scripts/gen_sample_pcapng.py --out fuzz/vehfuzz/samples/sample_eth.pcapng
python fuzz/vehfuzz/scripts/gen_sample_wifi_pcap.py --out fuzz/vehfuzz/samples/sample_wifi_radiotap.pcap
```

生成一个最小 Bluetooth HCI H4 pcap（linktype=187）：

```bash
python fuzz/vehfuzz/scripts/gen_sample_bt_pcap.py --out fuzz/vehfuzz/samples/sample_bt_hci_h4.pcap
python fuzz/vehfuzz/scripts/gen_sample_bt_pcap.py --mode sdp --out fuzz/vehfuzz/samples/sample_bt_sdp.pcap
python fuzz/vehfuzz/scripts/gen_sample_bt_pcap.py --mode rfcomm --out fuzz/vehfuzz/samples/sample_bt_rfcomm.pcap
```

运行 Wi-Fi / Bluetooth 离线示例（输出 `mutated.pcap`）：

```bash
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/wifi_pcap_offline
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/wifi_pcapng_offline
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/wifi_80211_pcap_offline
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/bluetooth_pcap_offline
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/bluetooth_sdp_pcap_offline
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/bluetooth_rfcomm_pcap_offline
```

## 7) 输出怎么看

每次运行会输出一个目录，例如：

`fuzz/vehfuzz/runs/<run_id>/`

重点看：

- `report.md`：Markdown 汇总
- `artifacts/events.jsonl`：逐用例日志
- `artifacts/summary.json`：结构化统计
- `artifacts/mutated.*`：离线输出语料（hex/nmea/candump/pcap）

## 备注（当前能力边界）

- Wi-Fi/Bluetooth 目前以 PCAP 离线变异为主；真实注入需要后续补 `Adapter`（监控模式/注入网卡、HCI 注入等）。
- DoIP/SOME-IP 目前实现的是最小“协议头封装 + payload 变异”，更深入的状态机/服务发现/会话保持后续再加。

## 8) boofuzz（可选）

安装 boofuzz 依赖（可选）：

```bash
python -m pip install -r fuzz/vehfuzz/requirements-boofuzz.txt
```

启动回环目标服务：

```bash
python fuzz/vehfuzz/scripts/targets/doip_server.py --port 13400
python fuzz/vehfuzz/scripts/targets/someip_server.py --port 30509
```

运行 boofuzz engine 示例：

```bash
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/boofuzz_doip
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/boofuzz_someip_udp
```

## 9) CANalyzat0r 导入（seeds）

示例（CANalyzat0r Project Export -> CAN seeds）：

```bash
python fuzz/vehfuzz/scripts/vehfuzz.py run --config-dir fuzz/vehfuzz/docs/examples/can_canalyzat0r_export
```
