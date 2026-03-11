use serde::{Deserialize, Serialize};

// Host(SecuXFlow) 환경에서 제공하는 FFI 함수 임포트
extern "C" {
    fn get_packet_size() -> i32;
    fn get_packet_data(offset: i32, len: i32) -> i32;
    fn log_alert(offset: i32, len: i32, severity: i32);
}

#[derive(Deserialize, Serialize)]
struct McpMessage {
    jsonrpc: String,
    method: Option<String>,
    params: Option<serde_json::Value>,
}

const BUFFER_SIZE: usize = 65536;
static mut PACKET_BUFFER: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];

#[no_mangle]
pub extern "C" fn inspect_packet() -> i32 {
    unsafe {
        let size = get_packet_size();
        if size <= 0 || size as usize > BUFFER_SIZE {
            return 0; // PASS
        }

        let copied = get_packet_data(PACKET_BUFFER.as_mut_ptr() as i32, size);
        if copied <= 0 {
            return 0; // PASS
        }

        // L2/L3/L4 헤더 오프셋 임의 적용 (불확실한 사실 참조)
        let header_offset = 54; 
        if copied as usize <= header_offset {
            return 0; // PASS
        }
        let payload = &PACKET_BUFFER[header_offset..copied as usize];

        // Payload JSON 파싱
        if let Ok(mcp_msg) = serde_json::from_slice::<McpMessage>(payload) {
            
            // 시나리오 1: 허가되지 않은 시스템 명령어 호출
            if let Some(method) = mcp_msg.method {
                if method == "execute_system_command" {
                    send_alert("Alert: Unauthorized Tool Calling detected.");
                    return 1; // DROP
                }
            }

            // 시나리오 2: 프롬프트 인젝션 패턴
            if let Some(params) = mcp_msg.params {
                let params_str = params.to_string();
                if params_str.contains("ignore previous instructions") {
                    send_alert("Alert: Prompt Injection pattern detected.");
                    return 1; // DROP
                }
            }
        }

        0 // PASS
    }
}

fn send_alert(message: &str) {
    unsafe {
        let msg_bytes = message.as_bytes();
        let len = msg_bytes.len() as i32;
        let ptr = msg_bytes.as_ptr() as i32;
        log_alert(ptr, len, 3);
    }
}
