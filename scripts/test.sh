#!/bin/bash
# SecuXFlow 테스트 스크립트

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# 현재 디렉토리 확인
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 빌드
echo -e "${YELLOW}SecuXFlow 빌드 중...${NC}"
cd "$PROJECT_ROOT"
cargo build

if [ $? -ne 0 ]; then
    echo -e "${RED}빌드 실패. 테스트를 중단합니다.${NC}"
    exit 1
fi

echo -e "${GREEN}빌드 성공!${NC}"

# 실행 파일 위치
EXEC="$PROJECT_ROOT/target/debug/secuxflow"

# 기본 상태 테스트
echo -e "\n${YELLOW}1. 상태 확인 테스트${NC}"
$EXEC status

# 규칙 추가 테스트
echo -e "\n${YELLOW}2. 규칙 추가 테스트${NC}"
$EXEC rule add --src 192.168.1.100 --dst 10.0.0.1 --port 80 --proto tcp --action drop
$EXEC rule add --src 192.168.1.200 --dst 10.0.0.2 --port 443 --proto tcp --action pass
$EXEC rule add --src 192.168.1.150 --port 53 --proto udp --action inspect

# 규칙 목록 테스트
echo -e "\n${YELLOW}3. 규칙 목록 테스트${NC}"
$EXEC rule list

# 패킷 검사 테스트
echo -e "\n${YELLOW}4. 패킷 검사 테스트${NC}"
$EXEC inspect --ip 192.168.1.100 --port 80 --proto tcp
$EXEC inspect --ip 10.0.0.5 --port 443 --proto tcp

# 규칙 삭제 테스트
echo -e "\n${YELLOW}5. 특정 규칙 삭제 테스트${NC}"
$EXEC rule delete --id "rule-1"

# 규칙 목록 재확인
echo -e "\n${YELLOW}6. 규칙 목록 재확인${NC}"
$EXEC rule list

# 모든 규칙 삭제 테스트
echo -e "\n${YELLOW}7. 모든 규칙 삭제 테스트${NC}"
$EXEC rule clear

# 규칙 목록 최종 확인
echo -e "\n${YELLOW}8. 규칙 목록 최종 확인${NC}"
$EXEC rule list

echo -e "\n${GREEN}모든 테스트가 완료되었습니다.${NC}"
