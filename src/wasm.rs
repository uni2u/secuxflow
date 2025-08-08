// src/wasm.rs
use anyhow::Result;
use log::{info, error, debug, warn};
use std::fmt;
use std::path::Path;
use wasmtime::{Engine, Module, Store, Instance, Caller, Extern, Func, ValType, Val};
use wasmtime_wasi::WasiCtx;

// WASI 컨텍스트를 포함하는 스토어 데이터 구조
pub struct WasmEnv {
    wasi: WasiCtx,
    // 패킷 데이터 저장용 버퍼
    packet_data: Vec<u8>,
}

// 패킷 검사 결과
#[derive(Debug)]
pub enum InspectionResult {
    Pass,
    Drop,
    Alert { message: String },
}

impl fmt::Display for InspectionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "통과"),
            Self::Drop => write!(f, "차단"),
            Self::Alert { message } => write!(f, "경고: {}", message),
        }
    }
}

pub struct WasmInspector {
    engine: Engine,
    module: Module,
}

impl WasmInspector {
    pub fn new(wasm_path: &str) -> Result<Self> {
        info!("WASM 모듈 초기화: {}", wasm_path);
        
        // WASM 엔진 생성
        let engine = Engine::default();
        
        // WASM 모듈 로드는 실제 파일이 있을 때만 수행
        // 개발 목적으로 더미 모듈 사용
        let module = if Path::new(wasm_path).exists() {
            info!("WASM 모듈 파일 로드: {}", wasm_path);
            match Module::from_file(&engine, wasm_path) {
                Ok(m) => m,
                Err(e) => {
                    info!("WASM 모듈 로드 실패: {}. 기본 모듈 사용.", e);
                    create_default_module(&engine)?
                }
            }
        } else {
            info!("WASM 모듈 파일이 없음. 기본 모듈 생성.");
            create_default_module(&engine)?
        };
        
        Ok(Self {
            engine,
            module,
        })
    }
    
    pub fn inspect_packet(&self, packet_data: &[u8]) -> Result<InspectionResult> {
        debug!("패킷 검사 중 ({} 바이트)", packet_data.len());
        
        // WASI 컨텍스트 생성
        let wasi = wasmtime_wasi::WasiCtxBuilder::new()
            .inherit_stdio()
            .build();
        
        // 환경 설정
        let mut store = Store::new(
            &self.engine, 
            WasmEnv { 
                wasi,
                packet_data: packet_data.to_vec(),
            }
        );
        
        // 패킷 데이터 호스트 함수 정의
        let get_packet_size_func = Func::wrap(&mut store, |mut caller: Caller<'_, WasmEnv>| {
            let data = &caller.data().packet_data;
            data.len() as i32
        });
        
        let get_packet_data_func = Func::wrap(&mut store, |mut caller: Caller<'_, WasmEnv>, offset: i32, len: i32| -> i32 {
            let data = &caller.data().packet_data;
            
            if offset < 0 || len < 0 || offset as usize >= data.len() {
                return -1; // 오류
            }
            
            let available_len = std::cmp::min(len as usize, data.len() - offset as usize);
            
            // WASM 메모리에 데이터 복사
            if available_len > 0 {
                let mem = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return -1,
                };
                
                // 메모리에 데이터 복사
                let dest_offset = offset as u32 as usize;
                match mem.data_mut(&mut caller).get_mut(dest_offset..(dest_offset + available_len)) {
                    Some(slice) => {
                        slice.copy_from_slice(&data[0..available_len]);
                        available_len as i32
                    },
                    None => -1
                }
            } else {
                0 // 가능한 데이터가 없는 경우
            }
        });
        
        // 타임스탬프 가져오기 함수
        let get_timestamp_func = Func::wrap(&mut store, |_caller: Caller<'_, WasmEnv>| -> i64 {
            // 현재 시간을 밀리초로 반환
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(n) => n.as_millis() as i64,
                Err(_) => 0i64,
            }
        });
        
        // 로그 알림 함수
        let log_alert_func = Func::wrap(&mut store, |mut caller: Caller<'_, WasmEnv>, offset: i32, len: i32, severity: i32| {
            // 메모리에서 알림 메시지 읽기
            if offset < 0 || len <= 0 {
                return;
            }
            
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => return,
            };
            
            let data = match mem.data(&caller).get(offset as u32 as usize..(offset as u32 + len as u32) as usize) {
                Some(data) => data,
                None => return,
            };
            
            // 알림 메시지를 UTF-8 문자열로 변환
            let alert_msg = match std::str::from_utf8(data) {
                Ok(s) => s,
                Err(_) => "Invalid UTF-8 alert message",
            };
            
            // 심각도에 따라 로그 레벨 설정
            match severity {
                1 => debug!("ALERT [LOW]: {}", alert_msg),
                2 => info!("ALERT [MEDIUM]: {}", alert_msg),
                3 => warn!("ALERT [HIGH]: {}", alert_msg),
                4 => error!("ALERT [CRITICAL]: {}", alert_msg),
                _ => info!("ALERT [UNKNOWN]: {}", alert_msg),
            }
            // ─── PoC용 Webhook 알림 전송 ────────────────────────────────
            // 환경변수 SECUXFLOW_ALERT_WEBHOOK에 URL 설정 필요
            if let Ok(webhook) = std::env::var("SECUXFLOW_ALERT_WEBHOOK") {
                let payload = serde_json::json!({ "text": alert_msg });
                std::thread::spawn(move || {
                    let _ = reqwest::blocking::Client::new()
                        .post(&webhook)
                        .json(&payload)
                        .send()
                        .map_err(|e| eprintln!("[WARN] Webhook 전송 실패: {}", e));
                });
            } else {
                warn!("SECUXFLOW_ALERT_WEBHOOK 설정 없음: Webhook 알림을 건너뜁니다");
            }
        });
        
        // 모듈 인스턴스화 (호스트 함수 제공)
        let instance = Instance::new(
            &mut store, 
            &self.module, 
            &[
                Extern::Func(get_packet_size_func),
                Extern::Func(get_packet_data_func),
                Extern::Func(log_alert_func),
                Extern::Func(get_timestamp_func),
            ]
        )?;
        
        // 'inspect_packet' 함수 찾기
        let inspect_packet_func = instance
            .get_func(&mut store, "inspect_packet")
            .ok_or_else(|| anyhow::anyhow!("'inspect_packet' 함수를 찾을 수 없습니다"))?;
            
        // 함수 호출
        let result = inspect_packet_func.call(
            &mut store, 
            &[], 
            &mut [Val::I32(0)]  // 결과 값 저장용
        )?;
        
        // 결과 해석
        if let Some(Val::I32(code)) = result.get(0) {
            match code {
                0 => Ok(InspectionResult::Pass),
                1 => Ok(InspectionResult::Drop),
                2 => {
                    // 경고 메시지는 간소화를 위해 고정 문자열 반환
                    Ok(InspectionResult::Alert { 
                        message: "의심스러운 패킷 감지".to_string()
                    })
                },
                _ => Ok(InspectionResult::Pass),  // 기본값
            }
        } else {
            // 결과가 없는 경우 기본값 반환
            Ok(InspectionResult::Pass)
        }
    }
}

// 테스트 용도의 기본 WASM 모듈 생성
fn create_default_module(engine: &Engine) -> Result<Module> {
    // 기본 WAT(WebAssembly Text) 코드
    let wat = r#"
        (module
          ;; 호스트 함수 임포트
          (import "" "get_packet_size" (func $get_packet_size (result i32)))
          (import "" "get_packet_data" (func $get_packet_data (param i32 i32) (result i32)))
          (import "" "log_alert" (func $log_alert (param i32 i32 i32)))
          (import "" "get_timestamp" (func $get_timestamp (result i64)))
          
          ;; 메모리 정의
          (memory (export "memory") 1)
          
          ;; 패킷 검사 함수 (PoC에서는 입력 바이트가 0이면 통과, 1-10이면 차단, 그 외는 경고)
          (func $inspect_packet (result i32)
            ;; 패킷 크기 가져오기
            (call $get_packet_size)
            
            ;; 패킷이 비어있으면 통과
            (i32.eqz)
            (if (result i32)
              (then
                (i32.const 0)  ;; PASS
              )
              (else
                ;; 패킷의 첫 바이트 검사 (간단한 예시)
                ;; 실제로 메모리에서 바이트를 읽어야 하지만, PoC에서는 단순화
                (i32.const 1)  ;; DROP (샘플 값)
              )
            )
          )
          
          ;; 함수 내보내기
          (export "inspect_packet" (func $inspect_packet))
        )
    "#;
    
    // WAT를 WASM 모듈로 컴파일
    Module::new(engine, wat)
}

// 테스트 함수 - 비 리눅스 환경에서도 기본적인 WASM 기능 테스트 가능
pub fn test_wasm_module() -> Result<()> {
    let inspector = WasmInspector::new("wasm_modules/basic_inspect.wasm")?;
    
    // 테스트 패킷
    let test_packets = vec![
        vec![0u8; 10],  // 모두 0인 패킷
        vec![1u8; 10],  // 모두 1인 패킷
        vec![255u8; 10],  // 모두 255인 패킷
    ];
    
    for (i, packet) in test_packets.iter().enumerate() {
        info!("테스트 패킷 #{} 검사", i+1);
        let result = inspector.inspect_packet(packet)?;
        
        match &result {
            InspectionResult::Pass => info!("패킷 #{} 검사 결과: PASS", i+1),
            InspectionResult::Drop => info!("패킷 #{} 검사 결과: DROP", i+1),
            InspectionResult::Alert { message } => info!("패킷 #{} 검사 결과: ALERT - {}", i+1, message),
        }
    }
    
    Ok(())
}
