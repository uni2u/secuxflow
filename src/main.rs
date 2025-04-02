// src/main.rs
use anyhow::Result;
use log::{info, warn};

mod cli;
#[cfg(target_os = "linux")]
mod xdp;
mod wasm;

fn main() -> Result<()> {
    // 로깅 초기화
    env_logger::init();
    
    info!("SecuXFlow starting up...");
    
    #[cfg(not(target_os = "linux"))]
    {
        warn!("XDP 기능은 Linux 환경에서만 사용 가능합니다.");
        warn!("현재 플랫폼에서는 WASM 모듈 및 CLI 인터페이스만 개발/테스트할 수 있습니다.");
    }
    
    #[cfg(target_os = "linux")]
    {
        info!("리눅스 환경 감지: 전체 기능 활성화");
        // 추후 XDP 기능 초기화 코드가 여기에 추가됩니다
    }
    
    // CLI 처리 (크로스 플랫폼)
    cli::run()?;
    
    info!("SecuXFlow 종료");
    Ok(())
}
