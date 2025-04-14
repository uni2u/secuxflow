#!/bin/bash
# SecuXFlow 개발 환경 설정 스크립트

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}SecuXFlow 개발 환경 설정을 시작합니다...${NC}"

# 현재 디렉토리 확인
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 필수 패키지 설치 (Ubuntu/Debian 기준)
if [ -f /etc/debian_version ]; then
    echo -e "${YELLOW}Ubuntu/Debian 시스템을 감지했습니다. 필수 패키지를 설치합니다...${NC}"
    
    sudo apt update
    sudo apt install -y build-essential \
                        llvm \
                        clang \
                        libelf-dev \
                        zlib1g-dev \
                        linux-headers-$(uname -r) \
                        wabt  # WAT를 WASM으로 컴파일하기 위한 도구
    
    # bpftool 설치 확인 및 설치
    if ! command -v bpftool &> /dev/null; then
        echo -e "${YELLOW}bpftool을 설치합니다...${NC}"
        sudo apt install -y linux-tools-$(uname -r) linux-tools-common
    fi
else
    echo -e "${YELLOW}Ubuntu/Debian 이외의 시스템입니다. 수동으로 필요한 패키지를 설치해주세요.${NC}"
    echo "필요한 패키지: build-essential, llvm, clang, libelf-dev, zlib1g-dev, linux-headers, bpftool, wabt"
fi

# Rust 설치 확인
if ! command -v rustc &> /dev/null; then
    echo -e "${YELLOW}Rust를 설치합니다...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo -e "${GREEN}Rust가 이미 설치되어 있습니다.${NC}"
fi

# Rust 버전 확인
RUST_VERSION=$(rustc --version | awk '{print $2}')
echo -e "${GREEN}Rust 버전: ${RUST_VERSION}${NC}"

# 필요한 디렉토리 생성
mkdir -p "$PROJECT_ROOT/wasm_modules"

# WAT 파일을 WASM으로 컴파일
if [ -f "$SCRIPT_DIR/compile_wasm.sh" ]; then
    echo -e "${YELLOW}WAT 파일을 WASM으로 컴파일합니다...${NC}"
    bash "$SCRIPT_DIR/compile_wasm.sh"
else
    echo -e "${RED}compile_wasm.sh 스크립트를 찾을 수 없습니다.${NC}"
fi

# 빌드 테스트
echo -e "${YELLOW}프로젝트 빌드를 테스트합니다...${NC}"
cd "$PROJECT_ROOT"
cargo build

if [ $? -eq 0 ]; then
    echo -e "${GREEN}빌드 성공! 개발 환경이 준비되었습니다.${NC}"
    echo ""
    echo -e "${GREEN}SecuXFlow 실행 방법:${NC}"
    echo -e "  ${YELLOW}개발 모드:${NC} cargo run"
    echo -e "  ${YELLOW}릴리스 모드:${NC} cargo run --release"
    echo ""
    echo -e "${GREEN}추가 명령어:${NC}"
    echo -e "  ${YELLOW}테스트 실행:${NC} cargo test"
    echo -e "  ${YELLOW}문서 생성:${NC} cargo doc --open"
else
    echo -e "${RED}빌드 실패. 오류를 확인해주세요.${NC}"
fi
