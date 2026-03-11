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

## System Requirements
### Minimum Requirements
- Linux kernel 5.4 or later (5.15+ recommended for optimal eBPF support)
- 2 CPU cores
- 4GB RAM
- 1GB free disk space

### Development Environment
- Ubuntu 22.04 LTS (recommended)
- Rust 1.70.0 (specified in rust-toolchain.toml)
- Administrative privileges (for installing packages and running XDP programs)

### Optional Dependencies
- For benchmarking: iperf, hping3, nmap
- For container tests: Docker

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

## Installation and Execution (Target: Ubuntu 22.04)

### Quick Start (Automated)
For a fresh Ubuntu 22.04 environment, you can set up and test the entire system with two commands:

```bash
# 1. Setup Environment (Installs dependencies and compiles WASM)
# This script will install llvm, clang, libbpf-dev, and wabt.
sudo ./scripts/setup_dev_env.sh

# 2. Run Automated Functional Tests
# This script builds the project and executes core CLI features.
sudo ./scripts/test.sh
```

### Manual Installation

#### 1. System Dependencies
```bash
sudo apt update
sudo apt install -y build-essential llvm clang libelf-dev zlib1g-dev \
                    libbpf-dev linux-headers-$(uname -r) wabt
```

#### 2. Compile WASM Modules
The system requires compiled WebAssembly binaries for packet inspection:
```bash
./scripts/compile_wasm.sh
```

#### 3. Build and Run
```bash
# Build the project
cargo build --release

# Run with root privileges (Required for XDP)
sudo ./target/release/secuxflow -i eth0
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
├── mcp_inspector/       # New: Rust-based L7 WASM module source
│   ├── src/lib.rs       # Stateful L7 inspection logic
│   └── Cargo.toml       # Fixed dependencies for Rust 1.70.0
└── scripts/             # Utility scripts
    ├── compile_wasm.sh  # WASM module compiler
    ├── setup_dev_env.sh # Development environment setup
    ├── build_rust_wasm.sh # New: Build script for Rust WASM
    ├── mcp_generator.py   # New: Scapy-based L7 traffic generator
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

## Troubleshooting
### Common Installation Issues
#### eBPF Loading Failures
If you encounter errors related to eBPF program loading:
```bash
# Check if your kernel supports BPF 
sudo bpftool feature

# Ensure you have the correct headers installed
sudo apt install -y linux-headers-$(uname -r)
```

### WASM Compilation Issues
If WebAssembly module compilation fails:
```bash
# Verify WABT is installed
wat2wasm --version

# Reinstall if needed
sudo apt install -y wabt
```

### Permission Issues
XDP functionality requires root privileges:
```bash
# Always run with sudo when using XDP features
sudo ./target/release/secuxflow
```

## Testing
To run basic functionality tests, you can use the following command:
```bash
./scripts/test.sh
```

## benchmark
### Running Benchmarks
```bash
# Make benchmark script executable
chmod +x benchmark.sh
chmod +x container_benchmark.sh

# Run basic performance comparison against Suricata
sudo ./benchmark.sh

# Run container-based benchmark tests
# DDoS test
sudo ./container_benchmark.sh ddos

# Port scan test
sudo ./container_benchmark.sh portscan

# Customize test parameters
DURATION=120 TEST_REPEAT=5 INTERFACE="ens33" TARGET_IP="192.168.1.50" ./container_benchmark.sh ddos
```

### Interpreting Results
Benchmark results are stored in the `benchmark_results` directory. Each test generates:
- CPU usage comparison
- Memory usage comparison
- Packet processing performance metrics
- Alert generation statistics

The `comparison.txt` file in each result directory provides a summary of the performance differences.

## Development and Extension

### Creating Custom WASM Modules
You can extend SecuXFlow with your own packet inspection modules:
1. Create a new WebAssembly Text (.wat) file in the `wasm_modules/` directory
2. Implement the `inspect_packet` function (see `basic_inspect.wat` for reference)
3. Compile using `./scripts/compile_wasm.sh`
4. Update the module path in your code or via CLI to use the new module

### Extending XDP Functionality
To add new XDP filtering capabilities:
1. Modify `bpf/xdp_filter.c` with your additional filtering logic
2. Update the corresponding user-space code in `src/xdp.rs`
3. Rebuild the project with `cargo build`

## License
This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

## Contributing
This project is in its early stages, and contribution guidelines will be provided in the future.

## L7 MCP Inspection Guide (Research Replication)

This section provides instructions for replicating the L7-aware security results (e.g., Figure 3 in the paper) using the high-performance Rust-based WASM module.

### 1. Build the Rust WASM Module
Unlike the basic WAT modules, the MCP inspector requires a specific Rust-WASI build environment.
```bash
# This script uses the pre-configured Cargo.lock to ensure dependency compatibility with Rust 1.70.0.
./scripts/build_rust_wasm.sh
```

### 2. Run with Dynamic WASM Loading
SecuXFlow now supports switching between L4-only and L7-aware inspection at runtime via environment variables.
```bash
# Execute with the L7 MCP inspector (Dynamic Loading)
sudo WASM_MODULE=wasm_modules/mcp_inspector.wasm ./target/release/secuxflow --iface eth0
```

### 3. L7 Traffic Testing (MCP Scenario)
To verify the L7 stateful inspection, use the specialized Python traffic generator.
```bash
# Requirements: pip install scapy
# It tests three scenarios: Normal, Unauthorized Tool Call, and Prompt Injection.
sudo python3 scripts/mcp_generator.py --iface eth0 --dst-ip <TARGET_IP>
```
