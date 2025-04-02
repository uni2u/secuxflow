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
secuxflow-cli [COMMAND] [OPTIONS]
```

### Rule Management
#### Add a new XDP filtering rule:
```
secuxflow-cli rule add --src 192.168.1.0/24 --dst 10.0.0.5 --port 80 --proto tcp --action drop
```

#### List all active rules:
```
secuxflow-cli rule list
```

#### Delete a specific rule:
```
secuxflow-cli rule delete --id 42
```

#### Clear all rules:
```
secuxflow-cli rule clear
```

### WASM Module Forwarding
#### Configure traffic forwarding to WASM modules:
```
secuxflow-cli forward add --src any --dst 10.0.0.0/24 --port 443 --proto tcp --module ips
```

#### List forwarding rules:
```
secuxflow-cli forward list
```

### System Status
#### Show current system status:
```
secuxflow-cli status show
```

#### Display traffic statistics:
```
secuxflow-cli status stats --interval 5s
```

## Key Features
- High-performance packet filtering at the kernel level using eBPF-XDP
- Dynamic rule configuration via CLI
- Advanced packet inspection through WASM modules
- Efficient traffic forwarding to containerized services
- Alert system for suspicious traffic patterns
- Admin-controlled rule generation based on WASM module analysis

## Project Structure
[TBD]

## Building and Running
[TBD]
Detailed setup instructions will be added as development progresses.

## License
[TBD]
