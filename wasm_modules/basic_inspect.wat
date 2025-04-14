(module
  ;; 호스트 함수 임포트
  (import "" "get_packet_size" (func $get_packet_size (result i32)))
  (import "" "get_packet_data" (func $get_packet_data (param i32 i32) (result i32)))
  
  ;; 메모리 정의
  (memory (export "memory") 1)
  
  ;; 패킷 버퍼용 위치
  (global $buffer_pos i32 (i32.const 1024))
  
  ;; 간단한 패킷 필터링 함수
  ;; 반환 값:
  ;;   0 = PASS (통과)
  ;;   1 = DROP (차단)
  ;;   2 = ALERT (경고)
  (func $inspect_packet (result i32)
    (local $packet_size i32)
    (local $first_byte i32)
    
    ;; 패킷 크기 가져오기
    call $get_packet_size
    local.set $packet_size
    
    ;; 패킷이 비어있으면 통과
    local.get $packet_size
    i32.eqz
    if (result i32)
      then
        i32.const 0  ;; PASS
        return
    end
    
    ;; 패킷 데이터의 첫 바이트를 버퍼로 가져오기
    (call $get_packet_data
      (global.get $buffer_pos)  ;; 버퍼 위치
      (i32.const 1)             ;; 1바이트만 필요
    )
    drop  ;; 결과 무시 (실제 구현에서는 오류 확인 필요)
    
    ;; 메모리에서 첫 바이트 읽기
    (i32.load8_u (global.get $buffer_pos))
    local.set $first_byte
    
    ;; 간단한 필터링 로직 (PoC 예시)
    ;; 첫 바이트가 0이면 통과
    local.get $first_byte
    i32.eqz
    if (result i32)
      then
        i32.const 0  ;; PASS
      else
        ;; 첫 바이트가 1-10 범위면 차단
        local.get $first_byte
        i32.const 1
        i32.ge_u
        local.get $first_byte
        i32.const 10
        i32.le_u
        i32.and
        if (result i32)
          then
            i32.const 1  ;; DROP
          else
            i32.const 2  ;; ALERT
        end
    end
  )
  
  ;; 함수 내보내기
  (export "inspect_packet" (func $inspect_packet))
)
