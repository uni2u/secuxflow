// src/cli.rs
use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

#[derive(Parser)]
#[clap(name = "secuxflow", about = "SecuXFlow XDP Filter with WASM Security Module")]
pub struct Cli {
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
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    
    match &cli.command {
        Some(Commands::Status) => {
            info!("시스템 상태 확인 중...");
            status_command()?;
        }
        
        #[cfg(target_os = "linux")]
        Some(Commands::Rule { action }) => {
            match action {
                RuleAction::Add { src, dst, port, proto, action } => {
                    info!("XDP 룰 추가: src={}, 액션={}", src, action);
                    // 룰 추가 구현은 리눅스 환경에서 추가 예정
                }
                RuleAction::List => {
                    info!("XDP 룰 목록 표시");
                    // 룰 목록 표시 구현은 리눅스 환경에서 추가 예정
                }
            }
        }
        
        None => {
            println!("사용 가능한 명령어를 보려면 --help를 사용하세요");
        }
    }
    
    Ok(())
}

fn status_command() -> Result<()> {
    println!("SecuXFlow 상태: 활성");
    
    #[cfg(target_os = "linux")]
    {
        println!("XDP 필터 활성화: 가능");
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        println!("XDP 필터 활성화: 불가능 (Linux 환경 필요)");
    }
    
    println!("WASM 모듈: 활성화됨");
    
    Ok(())
}
