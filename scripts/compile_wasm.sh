#!/bin/bash
# WAT 파일을 WASM 파일로 컴파일하는 스크립트

# 필요한 도구 확인
if ! command -v wat2wasm &> /dev/null; then
    echo "wat2wasm 도구가 필요합니다."
    echo "WABT(WebAssembly Binary Toolkit)를 설치하세요:"
    echo "  Ubuntu: sudo apt install wabt"
    echo "  macOS: brew install wabt"
    echo "  또는 https://github.com/WebAssembly/wabt 에서 다운로드"
    exit 1
fi

# 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WAT_DIR="$PROJECT_ROOT/wasm_modules"
WASM_DIR="$PROJECT_ROOT/wasm_modules"

# 디렉토리 존재 확인
mkdir -p "$WASM_DIR"

# 모든 WAT 파일을 WASM으로 컴파일
echo "WAT 파일을 WASM으로 컴파일 중..."
for wat_file in "$WAT_DIR"/*.wat; do
    if [ -f "$wat_file" ]; then
        filename=$(basename -- "$wat_file")
        wasm_file="$WASM_DIR/${filename%.wat}.wasm"
        echo "컴파일: $wat_file -> $wasm_file"
        wat2wasm "$wat_file" -o "$wasm_file"
        
        if [ $? -eq 0 ]; then
            echo "  성공!"
        else
            echo "  실패: wat2wasm 오류"
            exit 1
        fi
    fi
done

# 특정 WAT 파일이 없는 경우 기본 파일 생성
if [ ! -f "$WAT_DIR/basic_inspect.wat" ]; then
    echo "기본 검사 모듈 WAT 파일이 없습니다. 기본 템플릿을 생성합니다."
    cat > "$WAT_DIR/basic_inspect.wat" << 'EOF'
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
    
    ;; PoC에서는 모든 패킷에 대해 통과 반환
    i32.const 0  ;; PASS
  )
  
  ;; 함수 내보내기
  (export "inspect_packet" (func $inspect_packet))
)
EOF

    # 새로 생성된 WAT 파일을 WASM으로 컴파일
    echo "컴파일: $WAT_DIR/basic_inspect.wat -> $WASM_DIR/basic_inspect.wasm"
    wat2wasm "$WAT_DIR/basic_inspect.wat" -o "$WASM_DIR/basic_inspect.wasm"
    
    if [ $? -eq 0 ]; then
        echo "  성공!"
    else
        echo "  실패: wat2wasm 오류"
        exit 1
    fi
fi

echo "모든 WAT 파일이 WASM으로 컴파일되었습니다."
exit 0
