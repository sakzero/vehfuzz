# vehfuzz Architecture

## Overview

vehfuzz is a modular vehicle protocol fuzzing framework with a plugin-based architecture.

## Layer Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│                      (cli.py)                                │
│  - Command line interface                                    │
│  - Configuration loading                                     │
│  - Run management                                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Engine Layer                             │
│                    (engine.py)                               │
│  - Fuzzing loop orchestration                                │
│  - Seed loading and mutation                                 │
│  - Event logging                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Plugin System Layer                         │
│                    (plugins.py)                              │
│  - Abstract interfaces (Adapter, Protocol, Oracle)           │
│  - Plugin registration and factory                           │
│  - Message data structure                                    │
└─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│    Adapters     │ │   Protocols     │ │    Oracles      │
│                 │ │                 │ │                 │
│ - tcp           │ │ - raw           │ │ - basic         │
│ - udp           │ │ - can           │ │                 │
│ - socketcan     │ │ - uds           │ │                 │
│ - serial        │ │ - doip          │ │                 │
│ - doip          │ │ - someip        │ │                 │
│ - null (pcap)   │ │ - j1939         │ │                 │
│                 │ │ - nmea          │ │                 │
│                 │ │ - wifi          │ │                 │
│                 │ │ - bluetooth     │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

## Core Interfaces

### Message

The universal data container passed between layers:

```python
@dataclass(frozen=True)
class Message:
    data: bytes              # Raw message bytes
    meta: dict[str, Any]     # Protocol-specific metadata
```

### Adapter

Hardware/network communication interface:

```python
class Adapter(ABC):
    def open(self) -> None: ...
    def close(self) -> None: ...
    def send(self, msg: Message) -> None: ...
    def recv(self, timeout_s: float) -> Message | None: ...
```

### Protocol

Message construction and parsing:

```python
class Protocol(ABC):
    def build_tx(self, seed: Message, mutated: bytes) -> Message: ...
    def parse(self, msg: Message) -> ParsedMessage | None: ...
```

### Oracle

Anomaly detection:

```python
class Oracle(ABC):
    def on_tx(self, *, case_id: int, msg: Message) -> None: ...
    def on_rx(self, *, case_id: int, msg: Message) -> None: ...
    def on_error(self, *, case_id: int, error: str) -> None: ...
    def finalize(self) -> dict[str, Any]: ...
```

## Data Flow

```
                    ┌──────────────┐
                    │  Seed Corpus │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   Mutator    │
                    └──────┬───────┘
                           │ mutated bytes
                           ▼
┌──────────────────────────────────────────────────────────┐
│                      Protocol                             │
│                                                          │
│  seed + mutated ──► build_tx() ──► Message (with header) │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│                      Adapter                              │
│                                                          │
│  Message ──► send() ──► [Hardware/Network] ──► recv()    │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│                      Protocol                             │
│                                                          │
│  Message ──► parse() ──► ParsedMessage                   │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│                       Oracle                              │
│                                                          │
│  on_tx() / on_rx() / on_error() ──► finalize()           │
└──────────────────────────────────────────────────────────┘
```

## Shared Parsers

To avoid circular dependencies between protocols, shared parsing logic
lives in `core/parsers/`:

```
core/parsers/
├── __init__.py
├── uds_parser.py      # UDS payload parsing
├── doip_parser.py     # DoIP header parsing
└── ...
```

**Dependency Rule**: Protocols import from `core/parsers/`, never from each other.

```
┌─────────────────────────────────────────────────────────┐
│                    core/parsers/                         │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ uds_parser  │  │ doip_parser │  │ isotp       │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────┘
          ▲                 ▲                 ▲
          │                 │                 │
    ┌─────┴─────┐     ┌─────┴─────┐     ┌─────┴─────┐
    │  can.py   │     │  doip.py  │     │  uds.py   │
    └───────────┘     └───────────┘     └───────────┘
```

## Configuration

Configuration is YAML-based and drives component selection:

```yaml
# target.yaml
target:
  adapter:
    type: socketcan
    channel: vcan0

# campaign.yaml
campaign:
  protocol: can
  seed:
    type: candump
    path: ./samples/can.log

# oracle.yaml
oracle:
  type: basic
```

## Plugin Registration

Plugins self-register using decorators:

```python
@register_adapter("tcp")
def tcp_adapter(config: dict) -> Adapter:
    return _TcpAdapter(config)

@register_protocol("can")
def can_protocol(config: dict) -> Protocol:
    return _CanProtocol(config)

@register_oracle("basic")
def basic_oracle(config: dict) -> Oracle:
    return _BasicOracle(config)
```

Factory functions create instances:

```python
adapter = create_adapter("tcp", {"host": "127.0.0.1", "port": 13400})
protocol = create_protocol("doip", {"version": 0x02})
oracle = create_oracle("basic", {})
```
