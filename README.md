# secuxflow

secuxflow is a proof-of-concept network security system that combines eBPF-XDP based packet filtering with WASM modules for advanced traffic inspection.

## Project Overview

This system is designed to provide efficient network security in cloud-native and distributed environments, with a particular focus on performance and security in large-scale workload environments (data clusters, AI training clusters, etc.).

## System Architecture

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

### Key Components

- **XDP Filter**: Operates at the kernel network driver level to efficiently process packets
- **WASM Modules**: Provide advanced traffic inspection (IPS/WAF functionality)
- **CLI Interface**: Manage filtering rules and system configuration
- **Alert System**: Detect and notify about suspicious traffic patterns

## Key Features

- High-performance packet filtering at the kernel level using eBPF-XDP
- Extensible packet inspection through WASM modules
- Dynamic rule configuration via CLI
- Alert system for suspicious traffic patterns
- Efficient traffic forwarding to containerized services

## Prerequisites

### Linux Environment (Ubuntu 22.04 recommended)

```bash
sudo apt update
sudo apt install -y build-essential llvm clang libelf-dev zlib1g-dev bpftool linux-headers-$(uname -r) wabt
```

### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Installation and Execution

### Set Up Development Environment

```bash
# Make scripts executable
chmod +x scripts/compile_wasm.sh
chmod +x scripts/setup_dev_env.sh
chmod +x scripts/test.sh

# Automated development environment setup
./scripts/setup_dev_env.sh
```

### Compile WASM Modules

```bash
./scripts/compile_wasm.sh
```

### Build and Run

```bash
# Development build
cargo build

# Release build
cargo build --release

# Run in development mode
./target/debug/secuxflow

# Run in release mode
./target/release/secuxflow
```

## CLI Usage

SecuXFlow provides the following command-line interface:

### Basic Command Structure

```
secuxflow [COMMAND] [OPTIONS]
```

### Check System Status

```bash
secuxflow status
```

### Rule Management

#### Add a new XDP filtering rule:

```bash
secuxflow rule add --src 192.168.1.0/24 --dst 10.0.0.5 --port 80 --proto tcp --action drop
```

Supported actions:
- `pass`: Allow packet to pass through
- `drop`: Block packet
- `inspect`: Forward packet to WASM module for inspection

#### List active rules:

```bash
secuxflow rule list
```

#### Delete a specific rule:

```bash
secuxflow rule delete --id "rule-1"
```

#### Clear all rules:

```bash
secuxflow rule clear
```

### Test Packet Inspection

```bash
secuxflow inspect --ip 192.168.1.1 --port 443 --proto tcp
```

## Project Structure

```
secuxflow/
├── Cargo.toml           # Rust project configuration file
├── rust-toolchain.toml  # Rust version specification
├── README.md            # Project documentation
├── build.rs             # eBPF program build script
├── src/                 # Source code
│   ├── main.rs          # Main entry point
│   ├── cli.rs           # Command-line interface
│   ├── xdp.rs           # XDP filter implementation
│   ├── wasm.rs          # WASM module integration
│   └── chain.rs         # Service chaining implementation
├── bpf/                 # eBPF programs
│   ├── xdp_filter.c     # XDP filter program
│   └── common.h         # Common header
├── wasm_modules/        # WASM modules
│   ├── basic_inspect.wat # WASM text format module
│   └── basic_inspect.wasm # Compiled WASM module
└── scripts/             # Utility scripts
    ├── compile_wasm.sh  # WASM module compiler
    ├── setup_dev_env.sh # Development environment setup
    └── test.sh          # Test runner
```

## Limitations and Future Plans

This project is currently at the PoC stage with the following limitations:

- XDP functionality is only available in Linux environments (only WASM modules and CLI interface work on other platforms)
- Further environmental testing and performance optimization is needed
- Advanced packet inspection modules need to be developed

Future plans:
- Develop and extend more WASM modules
- Integrate real-time monitoring and analysis tools
- Develop deployment methods optimized for cloud-native environments
- Performance optimization for high-traffic environments

## Testing

To run basic functionality tests, you can use the following command:

```bash
./scripts/test.sh
```

## License

[TBD]

## Contributing

This project is in its early stages, and contribution guidelines will be provided in the future.
