// src/cli.rs
use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;
use std::sync::{Arc, Mutex};

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
pub fn run(xdp_filter: Option<Arc<Mutex<XdpFilter>>>, wasm_inspector: Option<Arc<WasmInspector>>) -> Result<()> {
    let cli = Cli::parse();

    // ─── 인터페이스 옵션 처리 ────────────────────────────────────
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
                    RuleAction::Add { src, dst, port, proto, action } => {
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
                    },
                }
            } else {
                println!("XDP 필터가 초기화되지 않았습니다.");
            }
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
