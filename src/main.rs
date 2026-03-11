// src/main.rs
use anyhow::Result;
use log::{info, warn};
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration};
use std::thread;

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
        let _service_chain = chain::ServiceChain::new(xdp_filter.clone(), wasm_inspector.clone());

        info!("시스템 초기화 완료 (k={})", k_val);
        cli::run(Some(xdp_filter.clone()), Some(wasm_inspector))?;

        // 3. [핵심 추가] 상주 모드 (Daemon) 및 벤치마크 지표 출력 루프
        // 프로그램이 종료되지 않고 유지되어야 테스트 스크립트가 트래픽을 주입하고 성능을 잴 수 있습니다.
        info!("SecuXFlow 상주(Daemon) 모드 진입. (Ctrl+C로 종료)");
        let start_time = Instant::now();
        let mut last_print = start_time;

        loop {
            // 1초마다 상태를 출력하여 container_benchmark.sh가 로그를 수집할 수 있게 함
            if last_print.elapsed() >= Duration::from_secs(1) {
                let elapsed_secs = start_time.elapsed().as_secs();

                // PoC 수준 지표 출력 (벤치마크 스크립트의 grep 대응용)
                // 향후 실제 eBPF Map에서 통계를 폴링하여 업데이트 가능
                println!("[METRIC] uptime: {}s, status: RUNNING, inspection_k: {}", elapsed_secs, k_val);
                last_print = Instant::now();
            }

            // [향후 확장 포인트] 커널에서 유저스페이스로 올라온 perf_event 처리
            // if let Ok(mut xdp) = xdp_filter.lock() {
            //     xdp.poll_events(Duration::from_millis(100))?;
            // } else {
            //     thread::sleep(Duration::from_millis(100));
            // }

            thread::sleep(Duration::from_millis(100));
        }
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
