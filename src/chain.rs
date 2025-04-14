// src/chain.rs
use anyhow::Result;
use log::{info, warn, error};
use std::sync::{Arc, Mutex};

use crate::wasm::{WasmInspector, InspectionResult};
use crate::xdp::XdpFilter;

/// 간단한 패킷 표현
pub struct Packet {
    pub data: Vec<u8>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: u8,
}

/// 서비스 체이닝 관리
pub struct ServiceChain {
    xdp_filter: Arc<Mutex<XdpFilter>>,
    wasm_inspector: Arc<WasmInspector>,
}

impl ServiceChain {
    pub fn new(xdp_filter: Arc<Mutex<XdpFilter>>, wasm_inspector: Arc<WasmInspector>) -> Self {
        Self {
            xdp_filter,
            wasm_inspector,
        }
    }

    /// 패킷 처리 체인 실행
    pub fn process_packet(&self, packet: &Packet) -> Result<()> {
        info!("패킷 처리: {} -> {}", packet.src_ip, packet.dst_ip);
        
        // WASM 모듈을 통한 패킷 검사
        match self.wasm_inspector.inspect_packet(&packet.data) {
            Ok(result) => {
                match result {
                    InspectionResult::Pass => {
                        info!("패킷 검사 결과: 통과");
                        // 패스 처리 - 아무것도 하지 않음
                    },
                    InspectionResult::Drop => {
                        info!("패킷 검사 결과: 차단 - XDP 룰 업데이트");
                        // XDP 필터에 차단 룰 추가
                        self.update_xdp_rules(&packet, "drop")?;
                    },
                    InspectionResult::Alert { message } => {
                        info!("패킷 검사 결과: 경고 - {}", message);
                        // 경고만 로깅, 차단하지 않음
                    }
                }
                Ok(())
            },
            Err(e) => {
                error!("패킷 검사 중 오류 발생: {}", e);
                Err(e)
            }
        }
    }

    /// XDP 필터링 룰 업데이트
    fn update_xdp_rules(&self, packet: &Packet, action: &str) -> Result<()> {
        let mut xdp = self.xdp_filter.lock().unwrap();
        
        // 소스 IP 기반 필터링 룰 추가
        xdp.add_rule(
            &packet.src_ip,
            Some(&packet.dst_ip),
            packet.dst_port,
            Some(match packet.protocol {
                6 => "tcp",
                17 => "udp",
                _ => "any"
            }),
            action
        )?;
        
        info!("XDP 필터링 룰 업데이트: {} -> {} ({})", 
            packet.src_ip, packet.dst_ip, action);
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy() {
        // 테스트 환경 설정을 위한 더미 테스트
        assert!(true);
    }
}
