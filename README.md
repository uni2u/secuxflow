# secuxflow
SecuXFlow is a proof-of-concept network security system that combines eBPF-XDP based packet filtering with WASM modules for advanced traffic inspection.

## Architecture
The system consists of the following components:

- XDP Filter: Operates at the kernel network driver level to efficiently process packets
- WASM Modules: Provide advanced traffic inspection (IPS/WAF functionality)
- CLI Interface: Allows administrators to configure filtering rules and actions
- Alert System: Notifies network administrators of suspicious traffic patterns

```
+------+        +------------+
| User | -----> | XDP Filter | -----+
+------+        +------------+      |
                     ^|             |     +-----------+
                     ||             +---> | Container |
                     ||                   | Service A |
                     |v                   +-----------+
               +-------------+
               | WASM Module |
               +-------------+
                     |
                     v
            +-----------------+       +------------------+       +------------+
            | Alert System    | ----> | Network Admin    | ----> | CLI Tool   |
            +-----------------+       +------------------+       +------------+
                                                                      |
                                                                      v
                                                                 +------------+
                                                                 | XDP Filter |
                                                                 +------------+
```

## Workflow
1. User traffic passes through the XDP Filter
2. XDP Filter performs basic filtering and forwards specific traffic to WASM modules
3. WASM modules inspect packets for suspicious patterns
4. If potential threats are detected, the Alert System notifies network administrators
5. Administrators can review alerts and create appropriate XDP filtering rules via CLI
6. New rules are applied to the XDP Filter to block similar traffic patterns at the kernel level

## CLI Usage
SecuXFlow provides a command-line interface for managing XDP filtering rules and WASM module configurations.

### Basic Commands
```
secuxflow [COMMAND] [OPTIONS]
```

### Rule Management
#### Add a new XDP filtering rule:
```
secuxflow rule add --src 192.168.1.0/24 --dst 10.0.0.5 --port 80 --proto tcp --action drop
```

#### List all active rules:
```
secuxflow rule list
```

#### Delete a specific rule:
```
secuxflow rule delete --id 42
```

#### Clear all rules:
```
secuxflow rule clear
```

### WASM Module Forwarding
```
secuxflow inspect --ip 192.168.1.1 --port 443 --proto tcp
```

### System Status
```
secuxflow status
```

## Key Features
- High-performance packet filtering at the kernel level using eBPF-XDP
- Dynamic rule configuration via CLI
- Advanced packet inspection through WASM modules
- Efficient traffic forwarding to containerized services
- Alert system for suspicious traffic patterns
- Admin-controlled rule generation based on WASM module analysis

## Project Structure
```
secuxflow/
├── Cargo.toml
├── rust-toolchain.toml
├── README.md
├── build.rs
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── xdp.rs
│   ├── wasm.rs
│   └── chain.rs
├── bpf/
│   ├── xdp_filter.c
│   └── common.h
└── wasm_modules/
    └── basic_inspect.wasm   # 새로 추가할 파일
```

## Building and Running
[TBD]

### Install Ubuntu Packages
```bash
sudo apt update
sudo apt install -y build-essential llvm clang libelf-dev zlib1g-dev bpftool linux-headers-$(uname -r)
```

### Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Build and Running
```bash
# develop mode build
cargo build

# release mode build
cargo build --release

# run
./target/debug/secuxflow
```

Detailed setup instructions will be added as development progresses.

## License
[TBD]
