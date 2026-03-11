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

    // 1. [위치 이동] 환경 변수 파싱을 최상단으로 이동 (모든 플랫폼 공통 사용)
    let k_val: u32 = std::env::var("INSPECT_K").unwrap_or_else(|_| "12".to_string()).parse().unwrap_or(12);
    
    #[cfg(not(target_os = "linux"))]
    {
        warn!("XDP 기능은 Linux 환경에서만 사용 가능합니다.");
        warn!("현재 플랫폼에서는 WASM 모듈 및 CLI 인터페이스만 개발/테스트할 수 있습니다.");
    }
    
    // WASM 모듈 초기화
    let wasm_path = std::env::var("WASM_MODULE").unwrap_or_else(|_| "wasm_modules/basic_inspect.wasm".to_string());
    let wasm_inspector = Arc::new(wasm::WasmInspector::new(&wasm_path)?);

    println!("[INFO] System initialized with inspection threshold k = {}", k_val);

    #[cfg(target_os = "linux")]
    {
        info!("Linux 환경 감지: XDP 기능 초기화 중...");

        // 1. XDP 필터 인스턴스 생성
        let mut filter_obj = xdp::XdpFilter::new()?;

        // 2. 생성된 인스턴스에 k값 주입
        filter_obj.set_k_threshold(k_val)?;

        let xdp_filter = Arc::new(Mutex::new(filter_obj));

        // 서비스 체이닝 초기화 및 이후 로직 (기존과 동일)
        let service_chain = chain::ServiceChain::new(xdp_filter.clone(), wasm_inspector.clone());

        info!("시스템 초기화 완료 (k={})", k_val);
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
