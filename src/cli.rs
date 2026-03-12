// src/cli.rs
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use log::info;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "linux")]
use crate::xdp::XdpFilter;
use crate::wasm::WasmInspector;

#[derive(Parser)]
#[clap(name = "secuxflow", about = "SecuXFlow - XDP Filter with WASM Security Module")]
pub struct Cli {
    /// Network interface to attach XDP program to (e.g. eth0)
    #[clap(short, long)]
    iface: Option<String>,
    
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// XDP 필터링 룰 관리
    #[cfg(target_os = "linux")]
    Rule {
        #[clap(subcommand)]
        action: RuleAction,
    },

    /// 엔진 상주 실행 (Suricata 비교 및 외부 트래픽 주입용)
    #[cfg(target_os = "linux")]
    Run,
    
    /// 패킷 검사 테스트
    Inspect {
        /// 테스트할 IP 주소
        #[clap(long)]
        ip: String,
        
        /// 테스트할 포트
        #[clap(long)]
        port: Option<u16>,
        
        /// 테스트할 프로토콜 (tcp/udp)
        #[clap(long)]
        proto: Option<String>,
    },
    
    /// 시스템 상태 확인
    Status,
}

#[cfg(target_os = "linux")]
#[derive(Subcommand)]
enum RuleAction {
    /// 새 룰 추가
    Add {
        #[clap(long)]
        src: String,
        #[clap(long)]
        dst: Option<String>,
        #[clap(long)]
        port: Option<u16>,
        #[clap(long)]
        proto: Option<String>,
        #[clap(long)]
        action: String,
    },
    /// 룰 목록 표시
    List,
    /// 특정 룰 삭제
    Delete {
        /// 삭제할 룰 ID
        #[clap(long)]
        id: String,
    },
    /// 모든 룰 삭제
    Clear,
}

#[cfg(target_os = "linux")]
pub fn run(xdp_filter: Option<Arc<Mutex<XdpFilter>>>, wasm_inspector: Option<Arc<WasmInspector>>,) -> Result<()> {
    let cli = Cli::parse();

    // 인터페이스 옵션 처리
    if let (Some(iface_name), Some(filter)) = (cli.iface.as_deref(), &xdp_filter) {
        info!("XDP 인터페이스 '{}' 에 attach 중...", iface_name);
        let mut xdp = filter.lock().unwrap();
        xdp.attach(iface_name)?;
    }
    
    match &cli.command {
        Some(Commands::Status) => {
            info!("시스템 상태 확인 중...");
            status_command(xdp_filter.is_some())?;
        },
        
        Some(Commands::Rule { action }) => {
            if let Some(filter) = &xdp_filter {
                match action {
                    RuleAction::Add { src, dst, port, proto, action, } => {
                        info!("XDP 룰 추가: src={}, 액션={}", src, action);
                        let mut xdp = filter.lock().unwrap();
                        match xdp.add_rule(src, dst.as_deref(), *port, proto.as_deref(), action) {
                            Ok(rule_id) => println!("룰이 추가되었습니다. ID: {}", rule_id),
                            Err(e) => println!("룰 추가 실패: {}", e),
                        }
                    },
                    RuleAction::List => {
                        info!("XDP 룰 목록 표시");
                        let xdp = filter.lock().unwrap();
                        let rules = xdp.list_rules()?;
                        
                        println!("현재 XDP 필터링 룰:");
                        for (i, rule) in rules.iter().enumerate() {
                            println!("{}: {}", i+1, rule);
                        }
                    },
                    RuleAction::Delete { id } => {
                        info!("XDP 룰 삭제: id={}", id);
                        let mut xdp = filter.lock().unwrap();
                        match xdp.delete_rule(&id) {
                            Ok(_) => println!("룰 ID '{}'가 삭제되었습니다.", id),
                            Err(e) => println!("룰 삭제 실패: {}", e),
                        }
                    },
                    RuleAction::Clear => {
                        info!("모든 XDP 룰 삭제");
                        let mut xdp = filter.lock().unwrap();
                        match xdp.clear_rules() {
                            Ok(_) => println!("모든 룰이 삭제되었습니다."),
                            Err(e) => println!("룰 삭제 실패: {}", e),
                        }
                    }
                }
            } else {
                println!("XDP 필터가 초기화되지 않았습니다.");
            }
        }

        Some(Commands::Run) => {
            let iface_name = cli
                .iface
                .as_deref()
                .ok_or_else(|| anyhow!("run 명령에는 --iface 옵션이 필요합니다."))?;

            let k_val: u32 = std::env::var("INSPECT_K")
                .unwrap_or_else(|_| "12".to_string())
                .parse()
                .unwrap_or(12);

            info!("엔진 상주 실행 시작: iface={}, k={}", iface_name, k_val);
            run_daemon(iface_name, k_val)?;
        }
        
        Some(Commands::Inspect { ip, port, proto }) => {
            info!("패킷 검사 테스트: IP={}", ip);
            inspect_command(ip, *port, proto.as_deref(), wasm_inspector)?;
        },
        
        None => {
            println!("사용 가능한 명령어를 보려면 --help를 사용하세요");
        },
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_daemon(iface_name: &str, k_val: u32) -> Result<()> {
    let metrics_path = resolve_metrics_path();
    let metrics_dir = metrics_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(metrics_dir)?;

    let needs_header = !metrics_path.exists() || fs::metadata(&metrics_path)?.len() == 0;
    let mut metrics_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&metrics_path)?;

    if needs_header {
        writeln!(
            metrics_file,
            "timestamp_epoch_ms,iface,rx_bytes,rx_kbps,cpu_usage_pct,memory_rss_kb"
        )?;
        metrics_file.flush()?;
    }

    let start = Instant::now();
    let mut prev_rx = read_rx_bytes(iface_name).unwrap_or(0);
    let mut prev_cpu = read_cpu_counters()?;

    println!(
        "SecuXFlow daemon running on '{}' (k={}). metrics={}",
        iface_name,
        k_val,
        metrics_path.display()
    );

    loop {
        thread::sleep(Duration::from_secs(1));

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("system time error: {}", e))?
            .as_millis();

        let current_rx = read_rx_bytes(iface_name).unwrap_or(prev_rx);
        let current_cpu = read_cpu_counters().unwrap_or(prev_cpu);
        let current_mem = read_memory_rss_kb().unwrap_or(0);

        let delta_rx = current_rx.saturating_sub(prev_rx);
        let rx_kbps = (delta_rx as f64 * 8.0) / 1000.0;

        let proc_delta = current_cpu.0.saturating_sub(prev_cpu.0) as f64;
        let total_delta = current_cpu.1.saturating_sub(prev_cpu.1) as f64;
        let cpu_usage_pct = if total_delta > 0.0 {
            (proc_delta / total_delta) * 100.0
        } else {
            0.0
        };

        writeln!(
            metrics_file,
            "{},{},{},{:.3},{:.3},{}",
            now_ms, iface_name, current_rx, rx_kbps, cpu_usage_pct, current_mem
        )?;
        metrics_file.flush()?;

        println!(
            "[METRIC] uptime_s={}, iface={}, rx_kbps={:.3}, cpu_usage_pct={:.3}, memory_rss_kb={}",
            start.elapsed().as_secs(),
            iface_name,
            rx_kbps,
            cpu_usage_pct,
            current_mem
        );

        // [향후 확장 포인트]
        // 여기에서 perf_event를 poll하여 inspect_map -> WASM 검사로 연결할 수 있습니다.

        prev_rx = current_rx;
        prev_cpu = current_cpu;
    }
}

#[cfg(target_os = "linux")]
fn resolve_metrics_path() -> PathBuf {
    std::env::var("SECUXFLOW_METRICS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("benchmark_results/metrics_secuxflow.csv"))
}

#[cfg(target_os = "linux")]
fn read_rx_bytes(iface_name: &str) -> Result<u64> {
    let path = format!("/sys/class/net/{}/statistics/rx_bytes", iface_name);
    let content = fs::read_to_string(path)?;
    Ok(content.trim().parse()?)
}

#[cfg(target_os = "linux")]
fn read_cpu_counters() -> Result<(u64, u64)> {
    let proc_stat = fs::read_to_string("/proc/self/stat")?;
    let proc_total = parse_proc_self_jiffies(&proc_stat)?;
    let cpu_total = parse_proc_total_jiffies(&fs::read_to_string("/proc/stat")?)?;
    Ok((proc_total, cpu_total))
}

#[cfg(target_os = "linux")]
fn read_memory_rss_kb() -> Result<u64> {
    let status = fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .ok_or_else(|| anyhow!("VmRSS line not found"))?;
    let value = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("VmRSS value missing"))?;
    Ok(value.parse()?)
}

#[cfg(target_os = "linux")]
fn parse_proc_self_jiffies(stat: &str) -> Result<u64> {
    let end = stat
        .rfind(')')
        .ok_or_else(|| anyhow!("failed to parse /proc/self/stat"))?;
    let fields: Vec<&str> = stat[(end + 2)..].split_whitespace().collect();
    if fields.len() <= 12 {
        return Err(anyhow!("unexpected /proc/self/stat format"));
    }

    let utime: u64 = fields[11].parse()?;
    let stime: u64 = fields[12].parse()?;
    Ok(utime + stime)
}

#[cfg(target_os = "linux")]
fn parse_proc_total_jiffies(stat: &str) -> Result<u64> {
    let first_line = stat
        .lines()
        .next()
        .ok_or_else(|| anyhow!("missing /proc/stat first line"))?;
    let mut parts = first_line.split_whitespace();
    if parts.next() != Some("cpu") {
        return Err(anyhow!("unexpected /proc/stat header"));
    }

    let total = parts
        .map(|p| p.parse::<u64>())
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .sum();
    Ok(total)
}

#[cfg(not(target_os = "linux"))]
pub fn run(_xdp_filter: Option<()>, wasm_inspector: Option<Arc<WasmInspector>>) -> Result<()> {
    let cli = Cli::parse();
    
    match &cli.command {
        Some(Commands::Status) => {
            info!("시스템 상태 확인 중...");
            status_command(false)?;
        },
        
        Some(Commands::Inspect { ip, port, proto }) => {
            info!("패킷 검사 테스트: IP={}", ip);
            inspect_command(ip, *port, proto.as_deref(), wasm_inspector)?;
        },
        
        None => {
            println!("사용 가능한 명령어를 보려면 --help를 사용하세요");
        },
    }
    
    Ok(())
}

fn status_command(xdp_available: bool) -> Result<()> {
    println!("SecuXFlow PoC 상태:");
    
    if xdp_available {
        println!("XDP 필터: 활성화됨");
    } else {
        println!("XDP 필터: 비활성화됨 (Linux 환경 필요)");
    }
    
    println!("WASM 모듈: 활성화됨");
    
    Ok(())
}

fn inspect_command(ip: &str, port: Option<u16>, proto: Option<&str>, wasm_inspector: Option<Arc<WasmInspector>>) -> Result<()> {
    if let Some(inspector) = wasm_inspector {
        println!("패킷 검사 테스트 실행:");
        println!("  IP 주소: {}", ip);
        if let Some(p) = port {
            println!("  포트: {}", p);
        }
        if let Some(p) = proto {
            println!("  프로토콜: {}", p);
        }
        
        // 간단한 패킷 데이터 생성 (실제로는 의미 없는 데이터)
        let test_packet = [0u8; 64];
        
        match inspector.inspect_packet(&test_packet) {
            Ok(result) => {
                println!("검사 결과: {:?}", result);
            },
            Err(e) => {
                println!("검사 중 오류 발생: {}", e);
            }
        }
    } else {
        println!("WASM 모듈이 초기화되지 않았습니다.");
    }
    
    Ok(())
}
