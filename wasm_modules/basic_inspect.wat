(module
  ;; 호스트 함수 임포트
  (import "" "get_packet_size" (func $get_packet_size (result i32)))
  (import "" "get_packet_data" (func $get_packet_data (param i32 i32) (result i32)))
  (import "" "log_alert" (func $log_alert (param i32 i32 i32))) ;; 로그 함수 (버퍼 오프셋, 길이, 심각도)
  (import "" "get_timestamp" (func $get_timestamp (result i64))) ;; 현재 타임스탬프 (밀리초)
  
  ;; 메모리 정의
  (memory (export "memory") 1)
  
  ;; 상수 정의
  (global $PACKET_BUFFER i32 (i32.const 0))      ;; 패킷 버퍼 시작 위치
  (global $CONNECTION_TABLE i32 (i32.const 8192))  ;; 연결 테이블 시작 위치
  (global $ALERT_BUFFER i32 (i32.const 16384))   ;; 알림 메시지 버퍼 시작 위치
  (global $DDOS_COUNTERS i32 (i32.const 32768))  ;; DDoS 카운터 시작 위치
  
  ;; 심각도 수준 상수
  (global $SEVERITY_LOW i32 (i32.const 1))
  (global $SEVERITY_MEDIUM i32 (i32.const 2))
  (global $SEVERITY_HIGH i32 (i32.const 3))
  (global $SEVERITY_CRITICAL i32 (i32.const 4))
  
  ;; 프로토콜 상수
  (global $PROTO_TCP i32 (i32.const 6))
  (global $PROTO_UDP i32 (i32.const 17))
  (global $PROTO_ICMP i32 (i32.const 1))
  
  ;; 패킷 분석 결과 상수
  (global $RESULT_PASS i32 (i32.const 0))    ;; 패킷 통과
  (global $RESULT_DROP i32 (i32.const 1))    ;; 패킷 차단
  (global $RESULT_ALERT i32 (i32.const 2))   ;; 경고만 (통과)
  
  ;; TCP 플래그 상수
  (global $TCP_FIN i32 (i32.const 1))
  (global $TCP_SYN i32 (i32.const 2))
  (global $TCP_RST i32 (i32.const 4))
  (global $TCP_PSH i32 (i32.const 8))
  (global $TCP_ACK i32 (i32.const 16))
  (global $TCP_URG i32 (i32.const 32))
  
  ;; 구성 매개변수
  (global $DDOS_THRESHOLD i32 (i32.const 1000))    ;; 초당 패킷 임계값
  (global $SCAN_PORT_THRESHOLD i32 (i32.const 10)) ;; 스캔 탐지 포트 임계값
  (global $TIME_WINDOW i64 (i64.const 5000))       ;; 타임 윈도우 (5초 = 5000ms)
  (global $PORT_SCAN_RANGE i32 (i32.const 30))     ;; 포트 스캔 범위 임계값
  
  ;; 초기화 함수
  (func $initialize_tables
    ;; 카운터 및 테이블 초기화 로직
    (i32.store (global.get $DDOS_COUNTERS) (i32.const 0))  ;; 총 패킷 카운터 초기화
    
    ;; 스캔 탐지 테이블 초기화 (포트당 접근 시간 등)
    (i32.store (global.get $CONNECTION_TABLE) (i32.const 0))
  )

  ;; IP 주소 해시 함수 (간단한 해싱)
  (func $hash_ip (param $ip i32) (result i32)
    (local $hash i32)
    (local.set $hash (i32.const 0))
    
    ;; 간단한 해싱 알고리즘
    (local.set $hash 
      (i32.xor 
        (local.get $ip)
        (i32.rotl 
          (local.get $ip)
          (i32.const 13)
        )
      )
    )
    
    ;; 해시 범위 제한 (0-255 사이의 인덱스)
    (i32.and (local.get $hash) (i32.const 0xFF))
  )
  
  ;; IP 헤더 파싱 함수
  (func $parse_ip_header (param $buffer_offset i32) (result i32 i32 i32 i32)
    (local $version_ihl i32)
    (local $protocol i32)
    (local $src_ip i32)
    (local $dst_ip i32)
    
    ;; 버전 및 IHL(IP Header Length) 읽기
    (local.set $version_ihl (i32.load8_u offset=0 (local.get $buffer_offset)))
    
    ;; 프로토콜 읽기 (9번째 바이트)
    (local.set $protocol (i32.load8_u offset=9 (local.get $buffer_offset)))
    
    ;; 소스 IP 읽기 (12-15번째 바이트)
    (local.set $src_ip (i32.load offset=12 (local.get $buffer_offset)))
    
    ;; 목적지 IP 읽기 (16-19번째 바이트)
    (local.set $dst_ip (i32.load offset=16 (local.get $buffer_offset)))
    
    ;; 반환: 버전_IHL, 프로토콜, 소스IP, 목적지IP
    (local.get $version_ihl)
    (local.get $protocol)
    (local.get $src_ip)
    (local.get $dst_ip)
  )
  
  ;; TCP 헤더 파싱 함수
  (func $parse_tcp_header (param $buffer_offset i32) (param $ihl i32) (result i32 i32 i32)
    (local $header_offset i32)
    (local $src_port i32)
    (local $dst_port i32)
    (local $flags i32)
    
    ;; IP 헤더 크기 계산 (IHL * 4)
    (local.set $header_offset 
      (i32.add 
        (local.get $buffer_offset)
        (i32.mul 
          (i32.and (local.get $ihl) (i32.const 0x0F))
          (i32.const 4)
        )
      )
    )
    
    ;; 소스 포트 읽기 (TCP 헤더의 첫 2바이트)
    (local.set $src_port (i32.load16_u offset=0 (local.get $header_offset)))
    
    ;; 목적지 포트 읽기 (TCP 헤더의 다음 2바이트)
    (local.set $dst_port (i32.load16_u offset=2 (local.get $header_offset)))
    
    ;; TCP 플래그 읽기 (13번째 바이트)
    (local.set $flags (i32.load8_u offset=13 (local.get $header_offset)))
    
    ;; 반환: 소스포트, 목적지포트, 플래그
    (local.get $src_port)
    (local.get $dst_port)
    (local.get $flags)
  )
  
  ;; UDP 헤더 파싱 함수
  (func $parse_udp_header (param $buffer_offset i32) (param $ihl i32) (result i32 i32)
    (local $header_offset i32)
    (local $src_port i32)
    (local $dst_port i32)
    
    ;; IP 헤더 크기 계산 (IHL * 4)
    (local.set $header_offset 
      (i32.add 
        (local.get $buffer_offset)
        (i32.mul 
          (i32.and (local.get $ihl) (i32.const 0x0F))
          (i32.const 4)
        )
      )
    )
    
    ;; 소스 포트 읽기 (UDP 헤더의 첫 2바이트)
    (local.set $src_port (i32.load16_u offset=0 (local.get $header_offset)))
    
    ;; 목적지 포트 읽기 (UDP 헤더의 다음 2바이트)
    (local.set $dst_port (i32.load16_u offset=2 (local.get $header_offset)))
    
    ;; 반환: 소스포트, 목적지포트
    (local.get $src_port)
    (local.get $dst_port)
  )
  
  ;; DDoS 탐지 함수
  (func $detect_ddos (param $src_ip i32) (param $protocol i32) (result i32)
    (local $ip_hash i32)
    (local $counter_offset i32)
    (local $packet_count i32)
    (local $timestamp i64)
    (local $last_timestamp i64)
    (local $time_diff i64)
    
    ;; 소스 IP 해싱
    (local.set $ip_hash (call $hash_ip (local.get $src_ip)))
    
    ;; IP별 카운터 위치 계산
    (local.set $counter_offset 
      (i32.add 
        (global.get $DDOS_COUNTERS) 
        (i32.mul (local.get $ip_hash) (i32.const 16))
      )
    )
    
    ;; 현재 카운터 값과 타임스탬프 읽기
    (local.set $packet_count (i32.load offset=0 (local.get $counter_offset)))
    (local.set $last_timestamp (i64.load offset=4 (local.get $counter_offset)))
    
    ;; 현재 타임스탬프 가져오기
    (local.set $timestamp (call $get_timestamp))
    
    ;; 시간 차이 계산
    (local.set $time_diff 
      (i64.sub (local.get $timestamp) (local.get $last_timestamp))
    )
    
    ;; 타임 윈도우보다 큰 경우 카운터 리셋
    (if (i64.gt_u (local.get $time_diff) (global.get $TIME_WINDOW))
      (then
        (local.set $packet_count (i32.const 1))  ;; 현재 패킷 포함하여 1로 설정
      )
      (else
        ;; 카운터 증가
        (local.set $packet_count (i32.add (local.get $packet_count) (i32.const 1)))
      )
    )
    
    ;; 업데이트된 카운터와 타임스탬프 저장
    (i32.store offset=0 (local.get $counter_offset) (local.get $packet_count))
    (i64.store offset=4 (local.get $counter_offset) (local.get $timestamp))
    
    ;; 프로토콜별 속도 제한 카운터 업데이트
    (if (i32.eq (local.get $protocol) (global.get $PROTO_TCP))
      (then
        (i32.store offset=12 (local.get $counter_offset) 
          (i32.add (i32.load offset=12 (local.get $counter_offset)) (i32.const 1))
        )
      )
    )
    (if (i32.eq (local.get $protocol) (global.get $PROTO_UDP))
      (then
        (i32.store offset=8 (local.get $counter_offset) 
          (i32.add (i32.load offset=8 (local.get $counter_offset)) (i32.const 1))
        )
      )
    )
    
    ;; 임계값 초과 여부 확인
    (if (i32.gt_u (local.get $packet_count) (global.get $DDOS_THRESHOLD))
      (then
        ;; 알림 생성
        (call $generate_ddos_alert (local.get $src_ip) (local.get $protocol) (local.get $packet_count))
        
        ;; DDoS 의심 패킷으로 차단 결정
        (return (global.get $RESULT_DROP))
      )
    )
    
    ;; 정상 트래픽으로 판단
    (global.get $RESULT_PASS)
  )
  
  ;; 포트 스캔 탐지 함수
  (func $detect_port_scan (param $src_ip i32) (param $dst_port i32) (param $flags i32) (result i32)
    (local $ip_hash i32)
    (local $scan_table_offset i32)
    (local $port_count i32)
    (local $timestamp i64)
    (local $last_timestamp i64)
    (local $is_syn_scan i32)
    
    ;; SYN 스캔 여부 확인 (SYN 플래그만 설정된 경우)
    (local.set $is_syn_scan 
      (i32.eq 
        (i32.and (local.get $flags) (global.get $TCP_SYN))
        (global.get $TCP_SYN)
      )
    )
    (if (i32.eqz (local.get $is_syn_scan))
      (then
        ;; SYN 스캔이 아니면 기본적으로 통과
        (return (global.get $RESULT_PASS))
      )
    )
    
    ;; 소스 IP 해싱
    (local.set $ip_hash (call $hash_ip (local.get $src_ip)))
    
    ;; IP별 스캔 테이블 위치 계산
    (local.set $scan_table_offset 
      (i32.add 
        (global.get $CONNECTION_TABLE) 
        (i32.mul (local.get $ip_hash) (i32.const 12))
      )
    )
    
    ;; 현재 포트 카운트와 타임스탬프 읽기
    (local.set $port_count (i32.load offset=0 (local.get $scan_table_offset)))
    (local.set $last_timestamp (i64.load offset=4 (local.get $scan_table_offset)))
    
    ;; 현재 타임스탬프 가져오기
    (local.set $timestamp (call $get_timestamp))
    
    ;; 타임 윈도우 체크 - 너무 오래된 기록이면 리셋
    (if (i64.gt_u 
          (i64.sub (local.get $timestamp) (local.get $last_timestamp))
          (global.get $TIME_WINDOW)
        )
      (then
        ;; 타임 윈도우 초과시 카운터 리셋
        (local.set $port_count (i32.const 1))
        
        ;; 최근 접근 포트 저장
        (i32.store offset=8 (local.get $scan_table_offset) (local.get $dst_port))
      )
      (else
        ;; 이전 접근 포트와 현재 포트가 연속적인지 확인
        (if (i32.gt_u 
              (i32.sub 
                (i32.abs 
                  (i32.sub 
                    (local.get $dst_port) 
                    (i32.load offset=8 (local.get $scan_table_offset))
                  )
                )
                (i32.const 1)
              )
              (global.get $PORT_SCAN_RANGE)
            )
          (then
            ;; 새로운 포트 범위 탐지, 카운터 증가
            (local.set $port_count (i32.add (local.get $port_count) (i32.const 1)))
            
            ;; 최근 접근 포트 업데이트
            (i32.store offset=8 (local.get $scan_table_offset) (local.get $dst_port))
          )
        )
      )
    )
    
    ;; 업데이트된 카운터와 타임스탬프 저장
    (i32.store offset=0 (local.get $scan_table_offset) (local.get $port_count))
    (i64.store offset=4 (local.get $scan_table_offset) (local.get $timestamp))
    
    ;; 임계값 초과 여부 확인
    (if (i32.gt_u (local.get $port_count) (global.get $SCAN_PORT_THRESHOLD))
      (then
        ;; 알림 생성
        (call $generate_scan_alert (local.get $src_ip) (local.get $port_count))
        
        ;; 포트 스캔 차단
        (return (global.get $RESULT_DROP))
      )
    )
    
    ;; 정상 트래픽으로 판단
    (global.get $RESULT_PASS)
  )
  
  ;; DDoS 알림 생성 함수
  (func $generate_ddos_alert (param $src_ip i32) (param $protocol i32) (param $count i32)
    (local $offset i32)
    (local $alert_len i32)
    
    ;; 알림 메시지 구성
    (local.set $offset (global.get $ALERT_BUFFER))
    
    ;; "DDoS Attack Detected" 메시지 작성
    (i32.store8 offset=0 (local.get $offset) (i32.const 68))  ;; 'D'
    (i32.store8 offset=1 (local.get $offset) (i32.const 68))  ;; 'D'
    (i32.store8 offset=2 (local.get $offset) (i32.const 111)) ;; 'o'
    (i32.store8 offset=3 (local.get $offset) (i32.const 83))  ;; 'S'
    (i32.store8 offset=4 (local.get $offset) (i32.const 32))  ;; ' '
    (i32.store8 offset=5 (local.get $offset) (i32.const 65))  ;; 'A'
    (i32.store8 offset=6 (local.get $offset) (i32.const 116)) ;; 't'
    (i32.store8 offset=7 (local.get $offset) (i32.const 116)) ;; 't'
    (i32.store8 offset=8 (local.get $offset) (i32.const 97))  ;; 'a'
    (i32.store8 offset=9 (local.get $offset) (i32.const 99))  ;; 'c'
    (i32.store8 offset=10 (local.get $offset) (i32.const 107)) ;; 'k'
    (i32.store8 offset=11 (local.get $offset) (i32.const 32)) ;; ' '
    (i32.store8 offset=12 (local.get $offset) (i32.const 68)) ;; 'D'
    (i32.store8 offset=13 (local.get $offset) (i32.const 101)) ;; 'e'
    (i32.store8 offset=14 (local.get $offset) (i32.const 116)) ;; 't'
    (i32.store8 offset=15 (local.get $offset) (i32.const 101)) ;; 'e'
    (i32.store8 offset=16 (local.get $offset) (i32.const 99)) ;; 'c'
    (i32.store8 offset=17 (local.get $offset) (i32.const 116)) ;; 't'
    (i32.store8 offset=18 (local.get $offset) (i32.const 101)) ;; 'e'
    (i32.store8 offset=19 (local.get $offset) (i32.const 100)) ;; 'd'
    
    ;; 알림 로그 기록
    (call $log_alert 
      (local.get $offset) 
      (i32.const 20) 
      (global.get $SEVERITY_HIGH)
    )
  )
  
  ;; 스캔 알림 생성 함수
  (func $generate_scan_alert (param $src_ip i32) (param $port_count i32)
    (local $offset i32)
    (local $alert_len i32)
    
    ;; 알림 메시지 구성
    (local.set $offset (global.get $ALERT_BUFFER))
    
    ;; "Port Scan Detected" 메시지 작성
    (i32.store8 offset=0 (local.get $offset) (i32.const 80))  ;; 'P'
    (i32.store8 offset=1 (local.get $offset) (i32.const 111)) ;; 'o'
    (i32.store8 offset=2 (local.get $offset) (i32.const 114)) ;; 'r'
    (i32.store8 offset=3 (local.get $offset) (i32.const 116)) ;; 't'
    (i32.store8 offset=4 (local.get $offset) (i32.const 32))  ;; ' '
    (i32.store8 offset=5 (local.get $offset) (i32.const 83))  ;; 'S'
    (i32.store8 offset=6 (local.get $offset) (i32.const 99))  ;; 'c'
    (i32.store8 offset=7 (local.get $offset) (i32.const 97))  ;; 'a'
    (i32.store8 offset=8 (local.get $offset) (i32.const 110)) ;; 'n'
    (i32.store8 offset=9 (local.get $offset) (i32.const 32))  ;; ' '
    (i32.store8 offset=10 (local.get $offset) (i32.const 68)) ;; 'D'
    (i32.store8 offset=11 (local.get $offset) (i32.const 101)) ;; 'e'
    (i32.store8 offset=12 (local.get $offset) (i32.const 116)) ;; 't'
    (i32.store8 offset=13 (local.get $offset) (i32.const 101)) ;; 'e'
    (i32.store8 offset=14 (local.get $offset) (i32.const 99)) ;; 'c'
    (i32.store8 offset=15 (local.get $offset) (i32.const 116)) ;; 't'
    (i32.store8 offset=16 (local.get $offset) (i32.const 101)) ;; 'e'
    (i32.store8 offset=17 (local.get $offset) (i32.const 100)) ;; 'd'
    
    ;; 알림 로그 기록
    (call $log_alert 
      (local.get $offset) 
      (i32.const 18) 
      (global.get $SEVERITY_MEDIUM)
    )
  )
  
  ;; 메인 패킷 검사 함수
  (func $inspect_packet (result i32)
    (local $packet_size i32)
    (local $result i32)
    (local $version_ihl i32)
    (local $protocol i32)
    (local $src_ip i32)
    (local $dst_ip i32)
    (local $src_port i32)
    (local $dst_port i32)
    (local $tcp_flags i32)
    
    ;; 초기화 - 실제 구현에서는 한 번만 호출되어야 함
    (call $initialize_tables)
    
    ;; 패킷 크기 가져오기
    (local.set $packet_size (call $get_packet_size))
    
    ;; 패킷이 비어있으면 통과
    (if (i32.eqz (local.get $packet_size))
      (then (return (global.get $RESULT_PASS)))
    )
    
    ;; 패킷이 IP 헤더보다 작으면 통과 (20바이트 미만)
    (if (i32.lt_u (local.get $packet_size) (i32.const 20))
      (then (return (global.get $RESULT_PASS)))
    )
    
    ;; 패킷 데이터 가져오기
    (call $get_packet_data 
      (global.get $PACKET_BUFFER) 
      (local.get $packet_size)
    )
    drop  ;; 반환값은 실제 읽은 바이트 수
    
    ;; IP 헤더 파싱
    (call $parse_ip_header (global.get $PACKET_BUFFER))
    (local.set $version_ihl)
    (local.set $protocol)
    (local.set $src_ip)
    (local.set $dst_ip)
    
    ;; DDoS 탐지 확인
    (local.set $result 
      (call $detect_ddos 
        (local.get $src_ip) 
        (local.get $protocol)
      )
    )
    
    ;; DDoS로 차단 결정되었다면 바로 반환
    (if (i32.eq (local.get $result) (global.get $RESULT_DROP))
      (then (return (global.get $RESULT_DROP)))
    )
    
    ;; TCP 패킷인 경우 추가 분석
    (if (i32.eq (local.get $protocol) (global.get $PROTO_TCP))
      (then
        ;; TCP 헤더 파싱
        (call $parse_tcp_header 
          (global.get $PACKET_BUFFER)
          (local.get $version_ihl)
        )
        (local.set $src_port)
        (local.set $dst_port)
        (local.set $tcp_flags)
        
        ;; 포트 스캔 탐지 확인
        (local.set $result 
          (call $detect_port_scan
            (local.get $src_ip)
            (local.get $dst_port)
            (local.get $tcp_flags)
          )
        )
        
        ;; 포트 스캔으로 차단 결정되었다면 바로 반환
        (if (i32.eq (local.get $result) (global.get $RESULT_DROP))
          (then (return (global.get $RESULT_DROP)))
        )
      )
    )
    
    ;; UDP 패킷인 경우 추가 분석
    (if (i32.eq (local.get $protocol) (global.get $PROTO_UDP))
      (then
        ;; UDP 헤더 파싱
        (call $parse_udp_header
          (global.get $PACKET_BUFFER)
          (local.get $version_ihl)
        )
        (local.set $src_port)
        (local.set $dst_port)
        
        ;; UDP 기반 추가 분석이 필요한 경우 여기에 구현
      )
    )
    
    ;; 기본 통과 결과
    (global.get $RESULT_PASS)
  )
  
  ;; 함수 내보내기
  (export "inspect_packet" (func $inspect_packet))
)
