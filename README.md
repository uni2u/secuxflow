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

## Installation and Execution
### Clone Repository
```bash
git clone https://github.com/uni2u/secuxflow.git
cd secuxflow
```

### Set Up Development Environment
```bash
# Make scripts executable
chmod +x scripts/compile_wasm.sh
chmod +x scripts/setup_dev_env.sh
chmod +x scripts/test.sh

# Linux or Mac (bash/zsh)
export SECUXFLOW_ALERT_WEBHOOK="https://hooks.example.com/your-path"
cargo run --release -- -i eth0 rule add --src 10.0.0.1 --action inspect

# Windows (PowerShell)
$Env:SECUXFLOW_ALERT_WEBHOOK="https://hooks.example.com/your-path"
cargo run --release -- -i eth0 rule add --src 10.0.0.1 --action inspect

# Automated development environment setup (requires sudo permission)
./scripts/setup_dev_env.sh
```
> **Note**: The setup script will install all necessary dependencies including build tools, eBPF dependencies, and check Rust installation.

### Compile WASM Modules
```bash
./scripts/compile_wasm.sh
```
> **Important**: This step creates the WebAssembly modules required for packet inspection.

### Build and Run
```bash
# Development build
cargo build

# Release build
cargo build --release
```

### Run the Application
```bash
# Development mode (requires root privileges for XDP functionality)
sudo ./target/debug/secuxflow

# OR in release mode
sudo ./target/release/secuxflow

# Run with specific network interface (recommended for real traffic inspection)
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
