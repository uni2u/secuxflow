#!/bin/bash
# benchmark.sh - SecuXFlow와 Suricata 성능 비교 스크립트

# 설정 변수
DURATION=60  # 테스트 지속 시간(초)
INTERFACE="eth0"  # 테스트 네트워크 인터페이스
TARGET_IP="192.168.1.100"  # 대상 IP
RESULTS_DIR="benchmark_results"
mkdir -p $RESULTS_DIR

# 시스템 사용량 모니터링 함수
monitor_system() {
  NAME=$1
  PIDSTAT_FILE="$RESULTS_DIR/${NAME}_pidstat.log"
  VMSTAT_FILE="$RESULTS_DIR/${NAME}_vmstat.log"
  
  # 프로세스 ID 찾기
  PID=$(pgrep -f $NAME)
  
  # CPU, 메모리 사용량 모니터링
  pidstat -p $PID 1 $DURATION > $PIDSTAT_FILE &
  vmstat 1 $DURATION > $VMSTAT_FILE &
}

# DDoS 테스트 실행
run_ddos_test() {
  echo "DDoS 테스트 시작 (${DURATION}초)..."
  iperf -c $TARGET_IP -u -b 5G -t $DURATION -P 8 > "$RESULTS_DIR/iperf_output.log" &
  IPERF_PID=$!
  
  # 동시에 SYN 플러드 생성
  hping3 -S --flood -p 80 $TARGET_IP > /dev/null 2>&1 &
  HPING_PID=$!
  
  # 지정된 시간 동안 대기
  sleep $DURATION
  
  # 트래픽 생성기 종료
  kill $IPERF_PID $HPING_PID 2>/dev/null
  wait $IPERF_PID $HPING_PID 2>/dev/null
  echo "DDoS 테스트 완료"
}

# 포트 스캔 테스트 실행
run_portscan_test() {
  echo "포트 스캔 테스트 시작..."
  
  # 여러 포트 범위에 대한 스캔 실행
  nmap -sS -T4 -p 1-1024 $TARGET_IP > "$RESULTS_DIR/nmap_scan1.log" &
  nmap -sS -D 10.0.0.1,10.0.0.2,ME -p 20-200 $TARGET_IP > "$RESULTS_DIR/nmap_scan2.log" &
  
  # 지정된 시간 동안 대기
  sleep $DURATION
  
  # 스캐너 종료
  pkill -f nmap
  echo "포트 스캔 테스트 완료"
}

# Suricata 테스트
test_suricata() {
  echo "Suricata 테스트 시작..."
  
  # Suricata 시작
  suricata -c /etc/suricata/suricata.yaml -i $INTERFACE > "$RESULTS_DIR/suricata_output.log" 2>&1 &
  SURICATA_PID=$!
  sleep 5  # 초기화 대기
  
  # 시스템 모니터링 시작
  monitor_system "suricata"
  
  # 트래픽 유형에 따라 테스트 실행
  if [ "$1" == "ddos" ]; then
    run_ddos_test
  else
    run_portscan_test
  fi
  
  # 결과 수집
  cp /var/log/suricata/stats.log "$RESULTS_DIR/suricata_stats.log"
  
  # Suricata 종료
  kill $SURICATA_PID
  wait $SURICATA_PID 2>/dev/null
  echo "Suricata 테스트 완료"
}

# SecuXFlow 테스트
test_secuxflow() {
  echo "SecuXFlow 테스트 시작..."
  
  # SecuXFlow 시작
  ./target/release/secuxflow > "$RESULTS_DIR/secuxflow_output.log" 2>&1 &
  SECUXFLOW_PID=$!
  sleep 5  # 초기화 대기
  
  # 시스템 모니터링 시작
  monitor_system "secuxflow"
  
  # 트래픽 유형에 따라 테스트 실행
  if [ "$1" == "ddos" ]; then
    run_ddos_test
  else
    run_portscan_test
  fi
  
  # SecuXFlow 종료
  kill $SECUXFLOW_PID
  wait $SECUXFLOW_PID 2>/dev/null
  echo "SecuXFlow 테스트 완료"
}

# 결과 분석
analyze_results() {
  echo "결과 분석 중..."
  
  # CPU 사용량 분석
  echo "=== CPU 사용량 비교 ===" > "$RESULTS_DIR/comparison.txt"
  echo "Suricata:" >> "$RESULTS_DIR/comparison.txt"
  awk '/Average:/ {print $3}' "$RESULTS_DIR/suricata_pidstat.log" | tail -1 >> "$RESULTS_DIR/comparison.txt"
  echo "SecuXFlow:" >> "$RESULTS_DIR/comparison.txt"
  awk '/Average:/ {print $3}' "$RESULTS_DIR/secuxflow_pidstat.log" | tail -1 >> "$RESULTS_DIR/comparison.txt"
  
  # 메모리 사용량 분석
  echo "=== 메모리 사용량 비교 ===" >> "$RESULTS_DIR/comparison.txt"
  echo "Suricata:" >> "$RESULTS_DIR/comparison.txt"
  awk '/Average:/ {print $12}' "$RESULTS_DIR/suricata_pidstat.log" | tail -1 >> "$RESULTS_DIR/comparison.txt"
  echo "SecuXFlow:" >> "$RESULTS_DIR/comparison.txt"
  awk '/Average:/ {print $12}' "$RESULTS_DIR/secuxflow_pidstat.log" | tail -1 >> "$RESULTS_DIR/comparison.txt"
  
  # 추가 분석 (필요시)
  
  echo "결과가 $RESULTS_DIR/comparison.txt에 저장되었습니다."
}

# 메인 실행 흐름
main() {
  TEST_TYPE=${1:-"ddos"}  # 기본값은 ddos
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  RESULTS_DIR="${RESULTS_DIR}/${TEST_TYPE}_${TIMESTAMP}"
  mkdir -p $RESULTS_DIR
  
  echo "벤치마크 시작: $TEST_TYPE"
  echo "결과 디렉토리: $RESULTS_DIR"
  
  # Suricata 테스트
  test_suricata $TEST_TYPE
  
  # 잠시 대기 (시스템 정리)
  sleep 10
  
  # SecuXFlow 테스트
  test_secuxflow $TEST_TYPE
  
  # 결과 분석
  analyze_results
  
  echo "벤치마크 완료!"
}

# 스크립트 실행
main "$@"
