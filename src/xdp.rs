// src/xdp.rs
#[cfg(target_os = "linux")]
use anyhow::{Result, anyhow};
#[cfg(target_os = "linux")]
use log::{info, warn, error};
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::str::FromStr;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use plain::Plain;

#[cfg(target_os = "linux")]
use crate::xdp_filter_skel::*;
#[cfg(target_os = "linux")]
use libbpf_rs::{MapFlags, Map};

#[cfg(target_os = "linux")]
// IP 프로토콜 상수
const IPPROTO_TCP: u8 = 6;
#[cfg(target_os = "linux")]
const IPPROTO_UDP: u8 = 17;

#[cfg(target_os = "linux")]
// BPF 맵에서 사용할 필터 키 구조체
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FilterKey {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

#[cfg(target_os = "linux")]
// Plain 트레이트 구현 (BPF 맵 사용을 위함)
unsafe impl Plain for FilterKey {}

#[cfg(target_os = "linux")]
// BPF 맵에서 사용할 필터 값 구조체
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FilterValue {
    action: u8,
}

#[cfg(target_os = "linux")]
// Plain 트레이트 구현 (BPF 맵 사용을 위함)
unsafe impl Plain for FilterValue {}

#[cfg(target_os = "linux")]
// XDP 액션 정의
pub enum XdpAction {
    Pass = 0,
    Drop = 1, 
    Inspect = 2,
}

#[cfg(target_os = "linux")]
/// XDP 필터 구조체
pub struct XdpFilter {
    // 스켈레톤 객체
    skel: Option<XdpFilterSkel>,
    // 인터페이스 이름 (XDP 프로그램이 연결된)
    interface: Option<String>,
    // 룰 데이터 캐시 (메모리 상에서 관리)
    rules: HashMap<String, (FilterKey, FilterValue)>,
}

#[cfg(target_os = "linux")]
impl XdpFilter {
    /// 새로운 XDP 필터 인스턴스 생성
    pub fn new() -> Result<Self> {
        info!("XDP 필터 초기화 중");
        
        // XDP 스켈레톤 빌더 생성
        let builder = XdpFilterSkelBuilder::new();
        
        // 스켈레톤 오픈 시도
        let open_result = builder.open();
        
        // XDP 프로그램 로드 시도 (실패 시 None)
        let skel = match open_result {
            Ok(mut open_skel) => {
                // 성공적으로 로드된 경우
                match open_skel.load() {
                    Ok(loaded_skel) => {
                        info!("XDP 프로그램 로드 성공");
                        Some(loaded_skel)
                    },
                    Err(e) => {
                        warn!("XDP 프로그램 로드 실패: {}. 개발 모드로 계속합니다.", e);
                        None
                    }
                }
            },
            Err(e) => {
                warn!("XDP 스켈레톤 오픈 실패: {}. 개발 모드로 계속합니다.", e);
                None
            }
        };
        
        Ok(Self {
            skel,
            interface: None,
            rules: HashMap::new(),
        })
    }
    
    /// 특정 네트워크 인터페이스에 XDP 프로그램 연결
    pub fn attach(&mut self, interface: &str) -> Result<()> {
        if let Some(skel) = &mut self.skel {
            info!("인터페이스 '{}' 에 XDP 프로그램 연결 시도", interface);
            
            // 일반적으로 여기서 libbpf의 attach 함수를 호출하여 
            // 인터페이스에 XDP 프로그램을 연결함
            // skel.progs().xdp_filter_prog().attach_xdp(interface)?;
            
            // PoC 수준에서는 단순화하여 실제 연결은 생략
            info!("XDP 프로그램 연결 성공 (PoC 모드)");
            self.interface = Some(interface.to_string());
            Ok(())
        } else {
            warn!("XDP 스켈레톤이 초기화되지 않아 연결할 수 없습니다.");
            Err(anyhow!("XDP 스켈레톤이 초기화되지 않았습니다."))
        }
    }
    
    /// XDP 필터링 룰 추가
    pub fn add_rule(&mut self, src: &str, dst: Option<&str>, port: Option<u16>, 
                   proto: Option<&str>, action: &str) -> Result<()> {
        info!("XDP 룰 추가: src={}, dst={:?}, port={:?}, proto={:?}, action={}", 
             src, dst, port, proto, action);
        
        // 소스 IP 파싱
        let src_ip = self.parse_ip(src)?;
        
        // 목적지 IP 파싱 (없으면 0.0.0.0 사용)
        let dst_ip = match dst {
            Some(dst_str) => self.parse_ip(dst_str)?,
            None => 0,
        };
        
        // 프로토콜 파싱
        let protocol = match proto {
            Some("tcp") => IPPROTO_TCP,
            Some("udp") => IPPROTO_UDP,
            _ => 0, // ANY
        };
        
        // 액션 파싱
        let xdp_action = match action.to_lowercase().as_str() {
            "pass" => XdpAction::Pass,
            "drop" => XdpAction::Drop,
            "inspect" => XdpAction::Inspect,
            _ => return Err(anyhow!("잘못된 액션: {}", action)),
        };
        
        // 필터 키와 값 생성
        let key = FilterKey {
            src_ip,
            dst_ip,
            src_port: 0,  // 현재 PoC 버전에서는 src_port는 사용하지 않음
            dst_port: port.unwrap_or(0),
            proto: protocol,
        };
        
        let value = FilterValue {
            action: xdp_action as u8,
        };
        
        // 룰 ID 생성 (소스 IP + 목적지 IP + 포트 + 프로토콜)
        let rule_id = format!("{}-{}-{}-{}", 
                             Ipv4Addr::from(src_ip.to_be()),
                             Ipv4Addr::from(dst_ip.to_be()),
                             port.unwrap_or(0),
                             protocol);
        
        // 룰을 BPF 맵에 추가
        if let Some(skel) = &self.skel {
            // 실제 BPF 맵 업데이트 시도
            if let Ok(filter_map) = skel.maps().filter_map() {
                // key와 value를 바이트 슬라이스로 변환
                let key_bytes = plain::as_bytes(&key);
                let value_bytes = plain::as_bytes(&value);
                
                match filter_map.update(key_bytes, value_bytes, MapFlags::ANY) {
                    Ok(_) => {
                        info!("BPF 맵에 룰 추가 성공: {}", rule_id);
                        // 로컬 캐시에도 룰 저장
                        self.rules.insert(rule_id, (key, value));
                        Ok(())
                    },
                    Err(e) => {
                        error!("BPF 맵 업데이트 실패: {}", e);
                        Err(anyhow!("BPF 맵 업데이트 오류: {}", e))
                    }
                }
            } else {
                // BPF 맵이 없는 경우 (개발 모드)
                warn!("BPF 맵 접근 실패. 메모리 캐시에만 룰 저장.");
                self.rules.insert(rule_id, (key, value));
                Ok(())
            }
        } else {
            // XDP 프로그램이 로드되지 않은 경우 (개발 모드)
            warn!("XDP 프로그램이 로드되지 않았습니다. 메모리 캐시에만 룰 저장.");
            self.rules.insert(rule_id, (key, value));
            Ok(())
        }
    }
    
    /// 현재 적용된 XDP 필터링 룰 목록 조회
    pub fn list_rules(&self) -> Result<Vec<String>> {
        let mut rules = Vec::new();
        
        // 실제 BPF 맵에서 룰 조회
        if let Some(skel) = &self.skel {
            if let Ok(filter_map) = skel.maps().filter_map() {
                info!("BPF 맵에서 룰 조회");
                
                // BPF 맵에서 모든 키-값 쌍 조회 (이 부분은 실제 환경에서 구현 필요)
                // 현재 PoC 환경에서는 메모리 캐시만 사용
                
                // 메모리 캐시의 룰을 문자열로 변환하여 추가
                for (rule_id, (key, value)) in &self.rules {
                    let action_str = match value.action {
                        0 => "PASS",
                        1 => "DROP",
                        2 => "INSPECT",
                        _ => "UNKNOWN",
                    };
                    
                    let rule_str = format!("{}: 소스 IP={}, 목적지 IP={}, 포트={}, 프로토콜={}, 액션={}",
                                        rule_id,
                                        Ipv4Addr::from(key.src_ip.to_be()),
                                        Ipv4Addr::from(key.dst_ip.to_be()),
                                        key.dst_port,
                                        match key.proto {
                                            6 => "TCP",
                                            17 => "UDP",
                                            _ => "ANY",
                                        },
                                        action_str);
                    rules.push(rule_str);
                }
            } else {
                warn!("BPF 맵 접근 실패. 메모리 캐시만 사용.");
                
                // 메모리 캐시만 사용
                for (rule_id, (key, value)) in &self.rules {
                    let action_str = match value.action {
                        0 => "PASS",
                        1 => "DROP", 
                        2 => "INSPECT",
                        _ => "UNKNOWN",
                    };
                    
                    let rule_str = format!("{}: 소스 IP={}, 목적지 IP={}, 포트={}, 프로토콜={}, 액션={}",
                                        rule_id,
                                        Ipv4Addr::from(key.src_ip.to_be()),
                                        Ipv4Addr::from(key.dst_ip.to_be()),
                                        key.dst_port,
                                        match key.proto {
                                            6 => "TCP",
                                            17 => "UDP",
                                            _ => "ANY",
                                        },
                                        action_str);
                    rules.push(rule_str);
                }
            }
        } else {
            warn!("XDP 프로그램이 로드되지 않았습니다. 메모리 캐시만 사용.");
            
            // 메모리 캐시만 사용
            for (rule_id, (key, value)) in &self.rules {
                let action_str = match value.action {
                    0 => "PASS",
                    1 => "DROP", 
                    2 => "INSPECT",
                    _ => "UNKNOWN",
                };
                
                let rule_str = format!("{}: 소스 IP={}, 목적지 IP={}, 포트={}, 프로토콜={}, 액션={}",
                                    rule_id,
                                    Ipv4Addr::from(key.src_ip.to_be()),
                                    Ipv4Addr::from(key.dst_ip.to_be()),
                                    key.dst_port,
                                    match key.proto {
                                        6 => "TCP",
                                        17 => "UDP",
                                        _ => "ANY",
                                    },
                                    action_str);
                rules.push(rule_str);
            }
        }
        
        // 룰이 없는 경우 샘플 룰 추가 (PoC 데모용)
        if rules.is_empty() {
            rules.push("샘플 룰 - PoC 모드".to_string());
        }
        
        Ok(rules)
    }
    
    /// 특정 룰 삭제
    pub fn delete_rule(&mut self, rule_id: &str) -> Result<()> {
        info!("룰 삭제: {}", rule_id);
        
        if let Some((key, _)) = self.rules.remove(rule_id) {
            // 실제 BPF 맵에서도 삭제
            if let Some(skel) = &self.skel {
                if let Ok(filter_map) = skel.maps().filter_map() {
                    let key_bytes = plain::as_bytes(&key);
                    match filter_map.delete(key_bytes) {
                        Ok(_) => {
                            info!("BPF 맵에서 룰 삭제 성공: {}", rule_id);
                        },
                        Err(e) => {
                            warn!("BPF 맵에서 룰 삭제 실패: {}", e);
                        }
                    }
                }
            }
            
            Ok(())
        } else {
            Err(anyhow!("룰 ID '{}' 를 찾을 수 없습니다.", rule_id))
        }
    }
    
    /// 모든 룰 삭제
    pub fn clear_rules(&mut self) -> Result<()> {
        info!("모든 룰 삭제");
        
        // 메모리 캐시 비우기
        self.rules.clear();
        
        // 실제 BPF 맵 비우기
        if let Some(skel) = &self.skel {
            if let Ok(filter_map) = skel.maps().filter_map() {
                info!("BPF 맵 비우기 시도");
                
                // BPF 맵 비우기 구현 (실제 환경에서 필요)
                // PoC 수준에서는 구현 생략
            }
        }
        
        Ok(())
    }
    
    /// IP 주소 문자열을 u32로 파싱
    fn parse_ip(&self, ip_str: &str) -> Result<u32> {
        match Ipv4Addr::from_str(ip_str) {
            Ok(addr) => Ok(u32::from_be(u32::from(addr))),
            Err(_) => Err(anyhow!("잘못된 IP 주소 형식: {}", ip_str)),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for XdpFilter {
    fn drop(&mut self) {
        info!("XDP 필터 정리 중");
        
        // 인터페이스가 설정된 경우, XDP 프로그램 분리
        if let Some(interface) = &self.interface {
            info!("인터페이스 '{}' 에서 XDP 프로그램 분리", interface);
            // 실제 분리 코드 (PoC에서는 생략)
        }
        
        // 기타 정리 작업
    }
}
