// src/main.rs
use anyhow::Result;
use log::{info, warn};
use std::sync::{Arc, Mutex};

mod cli;
#[cfg(target_os = "linux")]
mod xdp;
mod wasm;
mod chain;

// XDP 스켈레톤 파일 (build.rs에서 생성됨)
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "xdp_filter.skel.rs"]
mod xdp_filter_skel;

fn main() -> Result<()> {
    // 로깅 초기화
    env_logger::init();
    
    info!("SecuXFlow PoC 시작...");
    
    #[cfg(not(target_os = "linux"))]
    {
        warn!("XDP 기능은 Linux 환경에서만 사용 가능합니다.");
        warn!("현재 플랫폼에서는 WASM 모듈 및 CLI 인터페이스만 개발/테스트할 수 있습니다.");
    }
    
    // WASM 모듈 초기화
    let wasm_inspector = Arc::new(wasm::WasmInspector::new("wasm_modules/basic_inspect.wasm")?);
    
    #[cfg(target_os = "linux")]
    {
        info!("Linux 환경 감지: XDP 기능 초기화 중...");
        
        // XDP 필터 초기화
        let xdp_filter = Arc::new(Mutex::new(xdp::XdpFilter::new()?));
        
        // 서비스 체이닝 초기화
        let _service_chain = chain::ServiceChain::new(xdp_filter.clone(), wasm_inspector.clone());
        
        // CLI 처리
        cli::run(Some(xdp_filter), Some(wasm_inspector))?;
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        // 비 Linux 환경에서는 XDP 필터 없이 CLI 실행
        cli::run(None, Some(wasm_inspector))?;
        
        // WASM 모듈 테스트 실행
        wasm::test_wasm_module()?;
    }
    
    info!("SecuXFlow PoC 종료");
    Ok(())
}
