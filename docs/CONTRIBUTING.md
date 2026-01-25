# Contributing to vehfuzz

## Project Structure

```
vehfuzz/
├── src/vehfuzz/
│   ├── core/                    # Core engine and interfaces
│   │   ├── plugins.py           # Plugin interfaces (Adapter, Protocol, Oracle)
│   │   ├── parsers/             # Shared parsing functions
│   │   ├── schemas/             # Configuration schemas
│   │   ├── engine.py            # Fuzzing engine
│   │   └── ...
│   └── plugins/                 # Plugin implementations
│       ├── adapters/            # Hardware/network adapters
│       ├── protocols/           # Protocol handlers
│       └── oracles/             # Anomaly detectors
├── tests/
│   ├── contracts/               # Interface contract tests
│   ├── mocks/                   # Mock implementations
│   ├── unit/                    # Unit tests by module
│   └── integration/             # Integration tests
└── docs/                        # Documentation
```

## Development Workflow

### Setting Up

```bash
# Clone the repository
git clone <repo-url>
cd vehfuzz

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install in development mode
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/              # Unit tests only
pytest tests/contracts/         # Contract tests only
pytest tests/integration/       # Integration tests only

# Run tests for a specific module
pytest tests/unit/protocols/    # Protocol tests
pytest tests/unit/adapters/     # Adapter tests
```

### Code Style

- Use `ruff` for linting
- Use `mypy` for type checking
- Follow PEP 8 conventions

```bash
ruff check src/ tests/
mypy src/ --strict
```

## Adding New Components

### Adding a New Adapter

See [docs/adding-adapter.md](adding-adapter.md)

### Adding a New Protocol

See [docs/adding-protocol.md](adding-protocol.md)

### Adding a New Oracle

Similar pattern to adapters and protocols. Implement the `Oracle` interface.

## Architecture Principles

### Layer Separation

```
Application Layer (CLI)
        ↓
Engine Layer (engine.py)
        ↓
Plugin System (plugins.py)
        ↓
Implementations (adapters/, protocols/, oracles/)
```

### Dependency Rules

1. **Protocols MUST NOT depend on each other**
   - Use `core/parsers/` for shared parsing logic
   - Example: Both `can.py` and `doip.py` use `parsers/uds_parser.py`

2. **Adapters are independent**
   - Each adapter is self-contained
   - No adapter should import from another adapter

3. **Core modules are stable**
   - Changes to `plugins.py` interfaces require team discussion
   - All implementations must pass contract tests

### Data Flow

```
Seed Message → Protocol.build_tx() → Adapter.send()
                                          ↓
                                    Adapter.recv()
                                          ↓
                              Protocol.parse() → Oracle.on_rx()
```

## Testing Requirements

### Contract Tests

All plugin implementations MUST pass contract tests:

```python
# For adapters
class TestMyAdapter(AdapterContractMixin):
    @pytest.fixture
    def adapter_factory(self):
        return lambda: MyAdapter(config)

# For protocols
class TestMyProtocol(ProtocolContractMixin):
    @pytest.fixture
    def protocol_factory(self):
        return lambda: MyProtocol(config)
```

### Unit Tests

- Each new adapter/protocol should have dedicated unit tests
- Test edge cases (empty data, malformed input, etc.)
- Use mocks from `tests/mocks/` for isolation

## Pull Request Checklist

- [ ] Code follows project style guidelines
- [ ] All existing tests pass
- [ ] New code has appropriate test coverage
- [ ] Contract tests pass for new plugins
- [ ] Documentation updated if needed
- [ ] No new dependencies on other plugins (use core/parsers instead)
