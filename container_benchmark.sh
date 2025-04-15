#!/bin/bash
# container_benchmark.sh
# Suricata 컨테이너와 SecuXFlow(eBPF-XDP + WASM) 성능 비교 스크립트

set -e  # 오류 발생 시 스크립트 중단

# 색상 정의
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 설정 변수
DURATION=${DURATION:-60}  # 테스트 지속 시간(초), 환경 변수로 설정 가능
INTERFACE=${INTERFACE:-"eth0"}  # 호스트 네트워크 인터페이스
TARGET_IP=${TARGET_IP:-"192.168.1.100"}  # 대상 IP (실제 환경에 맞게 수정 필요)
BANDWIDTH=${BANDWIDTH:-5000}  # DDoS 테스트 대역폭 (Mbps)
RESULTS_DIR="benchmark_results"
TEST_REPEAT=${TEST_REPEAT:-3}  # 각 테스트 반복 횟수
SECUXFLOW_PATH=${SECUXFLOW_PATH:-"./target/release/secuxflow"}  # SecuXFlow 실행 파일 경로

# Suricata 컨테이너 이미지 및 태그
SURICATA_IMAGE="jasonish/suricata:latest"

# 테스트 시작 로그 함수
log_start() {
    echo -e "${GREEN}[$(date +"%T")] $1${NC}"
}

# 일반 로그 함수
log_info() {
    echo -e "${YELLOW}[$(date +"%T")] $1${NC}"
}

# 오류 로그 함수
log_error() {
    echo -e "${RED}[$(date +"%T")] $1${NC}"
}

# 디렉토리 생성 함수
create_test_dirs() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local test_dir="${RESULTS_DIR}/${TEST_TYPE}_${timestamp}"
    mkdir -p "$test_dir"
    mkdir -p "$test_dir/suricata"
    mkdir -p "$test_dir/secuxflow"
    echo "$test_dir"
}

# 스크립트 사전 요구사항 확인
check_prerequisites() {
    log_info "사전 요구사항 확인 중..."
    
    # Docker 확인
    if ! command -v docker &> /dev/null; then
        log_error "Docker가 설치되어 있지 않습니다. 설치 후 다시 시도하세요."
        exit 1
    fi
    
    # iperf 확인
    if ! command -v iperf &> /dev/null; then
        log_error "iperf가 설치되어 있지 않습니다. 설치 후 다시 시도하세요."
        log_info "설치 명령어: sudo apt-get install iperf"
        exit 1
    fi
    
    # nmap 확인 (포트 스캔 테스트용)
    if [ "$TEST_TYPE" == "portscan" ] && ! command -v nmap &> /dev/null; then
        log_error "nmap이 설치되어 있지 않습니다. 설치 후 다시 시도하세요."
        log_info "설치 명령어: sudo apt-get install nmap"
        exit 1
    fi
    
    # SecuXFlow 확인
    if [ ! -f "$SECUXFLOW_PATH" ]; then
        log_error "SecuXFlow 실행 파일($SECUXFLOW_PATH)을 찾을 수 없습니다."
        log_info "SECUXFLOW_PATH 환경 변수를 설정하거나 프로젝트를 빌드하세요."
        exit 1
    fi
    
    # 결과 디렉토리 생성
    mkdir -p "$RESULTS_DIR"
    
    log_info "사전 요구사항 확인 완료"
}

# Suricata 규칙 생성
create_suricata_rules() {
    local rules_dir="$1"
    log_info "Suricata 규칙 생성 중..."
    
    # 기본 suricata.yaml 구성 파일 생성
    cat > "${rules_dir}/suricata.yaml" << EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

default-rule-path: /etc/suricata/rules
rule-files:
  - custom.rules

af-packet:
  - interface: $INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    
detect-engine:
  - profile: medium
  - custom-values:
      toclient-src-groups: 2
      toclient-dst-groups: 2
      toclient-sp-groups: 2
      toclient-dp-groups: 3
      toserver-src-groups: 2
      toserver-dst-groups: 4
      toserver-sp-groups: 2
      toserver-dp-groups: 25
  - sgh-mpm-context: auto
  - inspection-recursion-limit: 3000

outputs:
  - fast:
      enabled: yes
      filename: /var/log/suricata/fast.log
  - stats:
      enabled: yes
      filename: /var/log/suricata/stats.log
      interval: 10
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - flow
        - stats
EOF
    
    # 테스트 유형에 따른 사용자 지정 규칙 생성
    if [ "$TEST_TYPE" == "ddos" ]; then
        cat > "${rules_dir}/custom.rules" << EOF
# DDoS 탐지 규칙
alert udp any any -> any any (msg:"UDP DDoS Flood detected"; flow:stateless; threshold: type both, track by_src, count 1000, seconds 1; sid:1000001; rev:1;)
alert tcp any any -> any any (msg:"TCP SYN Flood detected"; flags:S,12; flow:stateless; threshold: type both, track by_src, count 1000, seconds 1; sid:1000002; rev:1;)
EOF
    elif [ "$TEST_TYPE" == "portscan" ]; then
        cat > "${rules_dir}/custom.rules" << EOF
# 포트 스캔 탐지 규칙
alert tcp any any -> any any (msg:"Port Scan Detected"; flags:S,12; flow:stateless; threshold: type threshold, track by_src, count 5, seconds 1; sid:1000003; rev:1;)
EOF
    fi
    
    log_info "Suricata 규칙 생성 완료"
}

# Suricata 컨테이너 실행
run_suricata_container() {
    local output_dir="$1"
    log_start "Suricata 컨테이너 시작 중..."
    
    # 기존 Suricata 컨테이너 정리
    docker rm -f suricata-benchmark 2>/dev/null || true
    
    # Suricata 규칙 생성
    create_suricata_rules "$output_dir"
    
    # Suricata 컨테이너 실행
    docker run -d --name suricata-benchmark \
        --network host \
        --cap-add=NET_ADMIN --cap-add=SYS_NICE \
        -v "${output_dir}/suricata.yaml:/etc/suricata/suricata.yaml:ro" \
        -v "${output_dir}/custom.rules:/etc/suricata/rules/custom.rules:ro" \
        -v "${output_dir}:/var/log/suricata" \
        "$SURICATA_IMAGE" -i "$INTERFACE"
    
    # 초기화 대기 (Suricata가 모든 규칙을 로드하고 시작할 시간)
    log_info "Suricata 초기화 대기 중 (5초)..."
    sleep 5
    
    # 컨테이너가 실행 중인지 확인
    if ! docker ps --filter "name=suricata-benchmark" --format '{{.Names}}' | grep -q "suricata-benchmark"; then
        log_error "Suricata 컨테이너가 시작되지 않았습니다. 로그 확인:"
        docker logs suricata-benchmark
        exit 1
    fi
    
    log_info "Suricata 컨테이너 시작 완료"
}

# SecuXFlow 실행
run_secuxflow() {
    local output_dir="$1"
    log_start "SecuXFlow 시작 중..."
    
    # 이미 실행 중인 SecuXFlow 프로세스 종료
    pkill -f "$SECUXFLOW_PATH" 2>/dev/null || true
    
    # SecuXFlow 실행 (백그라운드로)
    $SECUXFLOW_PATH -i "$INTERFACE" > "${output_dir}/secuxflow.log" 2>&1 &
    SECUXFLOW_PID=$!
    
    # 프로세스가 시작되었는지 확인
    if ! ps -p $SECUXFLOW_PID > /dev/null; then
        log_error "SecuXFlow 시작 실패. 로그 확인: ${output_dir}/secuxflow.log"
        exit 1
    fi
    
    # 초기화 대기
    log_info "SecuXFlow 초기화 대기 중 (5초)..."
    sleep 5
    
    # 프로세스가 여전히 실행 중인지 확인
    if ! ps -p $SECUXFLOW_PID > /dev/null; then
        log_error "SecuXFlow가 비정상 종료되었습니다. 로그 확인: ${output_dir}/secuxflow.log"
        exit 1
    fi
    
    log_info "SecuXFlow 시작 완료 (PID: $SECUXFLOW_PID)"
    
    # PID 반환
    echo "$SECUXFLOW_PID"
}

# 시스템 성능 모니터링 시작
start_system_monitoring() {
    local output_file="$1"
    local pid="$2"
    local monitoring_duration="$3"
    local name="$4"
    
    log_info "${name} 시스템 모니터링 시작..."
    
    # vmstat를 사용하여 시스템 모니터링 (1초 간격)
    vmstat 1 "$monitoring_duration" > "${output_file}/vmstat.log" &
    VMSTAT_PID=$!
    
    # top을 사용하여 프로세스별 모니터링
    if [ -n "$pid" ]; then
        top -b -p "$pid" -d 1 -n "$monitoring_duration" > "${output_file}/top.log" &
        TOP_PID=$!
    else
        # Suricata 컨테이너의 경우 컨테이너 모니터링
        docker stats --no-stream suricata-benchmark > "${output_file}/docker_stats.log" &
        docker stats --no-trunc --format "{{.CPUPerc}},{{.MemUsage}},{{.NetIO}}" suricata-benchmark \
            > "${output_file}/container_stats.csv" &
        DOCKER_STATS_PID=$!
        
        # 지정된 시간 동안 주기적으로 컨테이너 통계 수집
        (
        for ((i=0; i<monitoring_duration; i++)); do
            docker stats --no-stream suricata-benchmark >> "${output_file}/docker_stats_full.log"
            sleep 1
        done
        ) &
        DOCKER_FULL_STATS_PID=$!
    fi
    
    # 네트워크 통계 수집
    ifstat -i "$INTERFACE" 1 "$monitoring_duration" > "${output_file}/ifstat.log" &
    IFSTAT_PID=$!
    
    # 메모리 세부 정보
    (
    for ((i=0; i<monitoring_duration; i++)); do
        echo "--- Memory Stats at $(date) ---" >> "${output_file}/memory_details.log"
        free -m >> "${output_file}/memory_details.log"
        sleep 1
    done
    ) &
    MEM_PID=$!
    
    # 모든 모니터링 PID 반환
    if [ -n "$pid" ]; then
        echo "$VMSTAT_PID $TOP_PID $IFSTAT_PID $MEM_PID"
    else
        echo "$VMSTAT_PID $DOCKER_STATS_PID $DOCKER_FULL_STATS_PID $IFSTAT_PID $MEM_PID"
    fi
}

# 모니터링 프로세스 종료
stop_monitoring() {
    local pids="$1"
    
    for pid in $pids; do
        kill $pid 2>/dev/null || true
    done
    
    log_info "시스템 모니터링 종료"
}

# DDoS 트래픽 생성
generate_ddos_traffic() {
    local output_dir="$1"
    
    log_start "DDoS 트래픽 생성 중 (${DURATION}초, ${BANDWIDTH}Mbps)..."
    
    # iperf로 UDP 플러드 생성
    log_info "UDP 플러드 시작 중..."
    iperf -c "$TARGET_IP" -u -b "${BANDWIDTH}M" -t "$DURATION" -P 8 > "${output_dir}/iperf_output.log" 2>&1 &
    IPERF_PID=$!
    
    # SYN 플러드 생성 (hping3 사용)
    # 실제 환경에서는 별도의 서버에서 실행하는 것이 좋음
    if command -v hping3 &> /dev/null; then
        log_info "SYN 플러드 시작 중..."
        sudo hping3 -S --flood -p 80 "$TARGET_IP" > /dev/null 2>&1 &
        HPING_PID=$!
    else
        log_info "hping3가 설치되어 있지 않아 SYN 플러드를 생성하지 않습니다."
        HPING_PID=""
    fi
    
    # 지정된 시간 동안 대기
    sleep "$DURATION"
    
    # 트래픽 생성 프로세스 종료
    if [ -n "$IPERF_PID" ]; then
        kill $IPERF_PID 2>/dev/null || true
    fi
    if [ -n "$HPING_PID" ]; then
        kill $HPING_PID 2>/dev/null || true
    fi
    
    log_info "DDoS 트래픽 생성 완료"
}

# 포트 스캔 트래픽 생성
generate_portscan_traffic() {
    local output_dir="$1"
    
    log_start "포트 스캔 트래픽 생성 중..."
    
    # 여러 포트 스캔 유형 실행
    log_info "TCP SYN 스캔 시작 중..."
    nmap -sS -T4 -p 1-1024 "$TARGET_IP" > "${output_dir}/nmap_scan1.log" 2>&1 &
    NMAP1_PID=$!
    
    log_info "위장 스캔 시작 중..."
    nmap -sS -D 10.0.0.1,10.0.0.2,ME -p 20-200 "$TARGET_IP" > "${output_dir}/nmap_scan2.log" 2>&1 &
    NMAP2_PID=$!
    
    # 무작위 포트 스캔 (여러 번 실행)
    log_info "무작위 포트 스캔 시작 중..."
    for i in $(seq 1 5); do
        local start_port=$((1000 + RANDOM % 10000))
        local end_port=$((start_port + 50 + RANDOM % 200))
        nmap -sS -T4 -p $start_port-$end_port "$TARGET_IP" > "${output_dir}/nmap_scan_random_${i}.log" 2>&1 &
        eval "NMAP_RANDOM_${i}_PID=$!"
    done
    
    # 지정된 시간 동안 대기
    sleep "$DURATION"
    
    # 스캔 프로세스 종료
    pkill -f nmap || true
    
    log_info "포트 스캔 트래픽 생성 완료"
}

# Suricata 결과 수집
collect_suricata_results() {
    local output_dir="$1"
    
    log_info "Suricata 결과 수집 중..."
    
    # eve.json 파일이 존재하는지 확인
    if [ -f "${output_dir}/eve.json" ]; then
        # eve.json에서 필요한 정보 추출
        log_info "이벤트 로그 분석 중..."
        grep "event_type" "${output_dir}/eve.json" | wc -l > "${output_dir}/event_count.txt"
        grep "alert" "${output_dir}/eve.json" | wc -l > "${output_dir}/alert_count.txt"
    fi
    
    # stats.log에서 성능 지표 추출
    if [ -f "${output_dir}/stats.log" ]; then
        log_info "성능 통계 분석 중..."
        # 마지막 통계 항목 추출
        grep "Date:" "${output_dir}/stats.log" | tail -1 > "${output_dir}/last_stats_time.txt"
        grep "decoder.pkts" "${output_dir}/stats.log" | tail -1 > "${output_dir}/packet_stats.txt"
        grep "decoder.bytes" "${output_dir}/stats.log" | tail -1 > "${output_dir}/bytes_stats.txt"
        grep "tcp.sessions" "${output_dir}/stats.log" | tail -1 > "${output_dir}/tcp_sessions.txt"
    fi
    
    # 컨테이너 리소스 사용량 요약
    if [ -f "${output_dir}/docker_stats_full.log" ]; then
        log_info "컨테이너 리소스 사용량 분석 중..."
        # 평균 CPU 사용률 계산
        grep -oP '\d+\.\d+%' "${output_dir}/docker_stats_full.log" | \
            awk '{ sum += substr($1, 1, length($1)-1); count++ } END { if (count > 0) print sum/count "%" }' \
            > "${output_dir}/avg_cpu_usage.txt"
        
        # 평균 메모리 사용량 계산
        grep -oP '\d+\.\d+MiB / \d+\.\d+MiB' "${output_dir}/docker_stats_full.log" | \
            awk '{ sum += substr($1, 1, index($1, "MiB")-1); count++ } END { if (count > 0) print sum/count " MiB" }' \
            > "${output_dir}/avg_memory_usage.txt"
    fi
    
    log_info "Suricata 결과 수집 완료"
}

# SecuXFlow 결과 수집
collect_secuxflow_results() {
    local output_dir="$1"
    
    log_info "SecuXFlow 결과 수집 중..."
    
    # SecuXFlow 로그 파일 확인
    if [ -f "${output_dir}/secuxflow.log" ]; then
        # 로그에서 성능 지표 추출
        log_info "로그 분석 중..."
        grep "packets processed" "${output_dir}/secuxflow.log" | tail -1 > "${output_dir}/packet_stats.txt"
        grep "alerts generated" "${output_dir}/secuxflow.log" | tail -1 > "${output_dir}/alert_stats.txt"
        grep "CPU usage" "${output_dir}/secuxflow.log" | tail -1 > "${output_dir}/cpu_usage.txt"
        grep "Memory usage" "${output_dir}/secuxflow.log" | tail -1 > "${output_dir}/memory_usage.txt"
    fi
    
    # top 로그 분석
    if [ -f "${output_dir}/top.log" ]; then
        log_info "프로세스 통계 분석 중..."
        grep "$SECUXFLOW_PATH" "${output_dir}/top.log" | \
            awk '{ sum_cpu += $9; sum_mem += $10; count++ } END { if (count > 0) print "Average CPU: " sum_cpu/count "%, Average Memory: " sum_mem/count "%" }' \
            > "${output_dir}/resource_usage_summary.txt"
    fi
    
    log_info "SecuXFlow 결과 수집 완료"
}

# 결과 비교 및 요약
compare_results() {
    local test_dir="$1"
    local repetition="$2"
    
    log_start "테스트 결과 비교 및 요약 생성 중..."
    
    # 요약 파일 생성
    local summary_file="${test_dir}/summary_${repetition}.txt"
    
    echo "==============================================" > "$summary_file"
    echo "  테스트 요약 보고서 (반복 $repetition)  " >> "$summary_file"
    echo "==============================================" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "테스트 유형: $TEST_TYPE" >> "$summary_file"
    echo "테스트 시간: $(date)" >> "$summary_file"
    echo "테스트 지속 시간: $DURATION 초" >> "$summary_file"
    echo "" >> "$summary_file"
    
    echo "-- Suricata 성능 --" >> "$summary_file"
    if [ -f "${test_dir}/suricata/avg_cpu_usage.txt" ]; then
        echo "평균 CPU 사용률: $(cat ${test_dir}/suricata/avg_cpu_usage.txt)" >> "$summary_file"
    fi
    if [ -f "${test_dir}/suricata/avg_memory_usage.txt" ]; then
        echo "평균 메모리 사용량: $(cat ${test_dir}/suricata/avg_memory_usage.txt)" >> "$summary_file"
    fi
    if [ -f "${test_dir}/suricata/packet_stats.txt" ]; then
        echo "처리된 패킷: $(cat ${test_dir}/suricata/packet_stats.txt)" >> "$summary_file"
    fi
    if [ -f "${test_dir}/suricata/alert_count.txt" ]; then
        echo "생성된 알림: $(cat ${test_dir}/suricata/alert_count.txt)" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    echo "-- SecuXFlow 성능 --" >> "$summary_file"
    if [ -f "${test_dir}/secuxflow/cpu_usage.txt" ]; then
        echo "CPU 사용률: $(cat ${test_dir}/secuxflow/cpu_usage.txt)" >> "$summary_file"
    elif [ -f "${test_dir}/secuxflow/resource_usage_summary.txt" ]; then
        echo "리소스 사용량: $(cat ${test_dir}/secuxflow/resource_usage_summary.txt)" >> "$summary_file"
    fi
    if [ -f "${test_dir}/secuxflow/memory_usage.txt" ]; then
        echo "메모리 사용량: $(cat ${test_dir}/secuxflow/memory_usage.txt)" >> "$summary_file"
    fi
    if [ -f "${test_dir}/secuxflow/packet_stats.txt" ]; then
        echo "처리된 패킷: $(cat ${test_dir}/secuxflow/packet_stats.txt)" >> "$summary_file"
    fi
    if [ -f "${test_dir}/secuxflow/alert_stats.txt" ]; then
        echo "생성된 알림: $(cat ${test_dir}/secuxflow/alert_stats.txt)" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    echo "==============================================" >> "$summary_file"
    
    # 결과 출력
    cat "$summary_file"
    
    log_info "결과 요약이 생성되었습니다: $summary_file"
}

# 최종 결과 보고서 생성
generate_final_report() {
    local test_dir="$1"
    
    log_start "최종 보고서 생성 중..."
    
    # 최종 보고서 파일 생성
    local report_file="${test_dir}/final_report.txt"
    
    echo "=============================================" > "$report_file"
    echo "  SecuXFlow vs Suricata 성능 비교 보고서  " >> "$report_file"
    echo "=============================================" >> "$report_file"
    echo "" >> "$report_file"
    echo "테스트 유형: $TEST_TYPE" >> "$report_file"
    echo "테스트 완료 시간: $(date)" >> "$report_file"
    echo "테스트 반복 횟수: $TEST_REPEAT" >> "$report_file"
    echo "테스트 지속 시간: $DURATION 초" >> "$report_file"
    echo "" >> "$report_file"
    
    # 여러 번의 테스트 결과 평균 계산
    echo "=== 평균 성능 지표 ===" >> "$report_file"
    
    # 여기에 평균 계산 로직 추가
    # (실제 구현에서는 테스트 결과에서 수치를 추출하여 평균 계산)
    
    echo "" >> "$report_file"
    echo "=== 성능 비교 결론 ===" >> "$report_file"
    echo "이 보고서는 자동 생성되었으며, 상세한 분석은 연구자의 해석이 필요합니다." >> "$report_file"
    echo "" >> "$report_file"
    echo "=============================================" >> "$report_file"
    
    # 결과 출력
    cat "$report_file"
    
    log_info "최종 보고서가 생성되었습니다: $report_file"
    log_info "모든 결과 데이터는 다음 위치에 저장되었습니다: $test_dir"
}

# Suricata 컨테이너 종료
stop_suricata_container() {
    log_info "Suricata 컨테이너 종료 중..."
    docker stop suricata-benchmark 2>/dev/null || true
    docker rm suricata-benchmark 2>/dev/null || true
    log_info "Suricata 컨테이너 종료 완료"
}

# SecuXFlow 종료
stop_secuxflow() {
    local pid="$1"
    log_info "SecuXFlow 종료 중 (PID: $pid)..."
    kill $pid 2>/dev/null || true
    # 프로세스가 완전히 종료되었는지 확인
    for i in {1..5}; do
        if ! ps -p $pid > /dev/null; then
            break
        fi
        sleep 1
    done
    # 여전히 실행 중이면 강제 종료
    if ps -p $pid > /dev/null; then
        kill -9 $pid 2>/dev/null || true
    fi
    log_info "SecuXFlow 종료 완료"
}

# 단일 테스트 실행 (Suricata 또는 SecuXFlow)
run_single_test() {
    local system="$1"  # "suricata" 또는 "secuxflow"
    local test_dir="$2"
    local repetition="$3"
    
    local system_dir="${test_dir}/${system}"
    mkdir -p "$system_dir"
    
    log_start "${system^} 테스트 실행 (#${repetition})..."
    
    # 시스템 시작
    local pid=""
    if [ "$system" == "suricata" ]; then
        run_suricata_container "$system_dir"
    else
        pid=$(run_secuxflow "$system_dir")
    fi
    
    # 모니터링 시작
    local monitor_pids=$(start_system_monitoring "$system_dir" "$pid" "$DURATION" "${system^}")
    
    # 트래픽 생성
    if [ "$TEST_TYPE" == "ddos" ]; then
        generate_ddos_traffic "$system_dir"
    elif [ "$TEST_TYPE" == "portscan" ]; then
        generate_portscan_traffic "$system_dir"
    else
        log_error "지원되지 않는 테스트 유형: $TEST_TYPE"
        exit 1
    fi
    
    # 모니터링 종료
    stop_monitoring "$monitor_pids"
    
    # 결과 수집
    if [ "$system" == "suricata" ]; then
        collect_suricata_results "$system_dir"
        stop_suricata_container
    else
        collect_secuxflow_results "$system_dir"
        stop_secuxflow "$pid"
    fi
    
    log_info "${system^} 테스트 #${repetition} 완료"
    
    # 시스템 정리 시간
    log_info "시스템 정리 중 (10초)..."
    sleep 10
}

# 테스트 루프 실행
run_test_loop() {
    local test_dir="$1"
    
    log_start "테스트 시작: $TEST_TYPE (총 $TEST_REPEAT회 반복)"
    
    for ((i=1; i<=$TEST_REPEAT; i++)); do
        log_start "테스트 반복 $i/$TEST_REPEAT 시작..."
        
        # Suricata 테스트
        run_single_test "suricata" "$test_dir" "$i"
        
        # SecuXFlow 테스트
        run_single_test "secuxflow" "$test_dir" "$i"
        
        # 결과 비교
        compare_results "$test_dir" "$i"
        
        log_info "테스트 반복 $i/$TEST_REPEAT 완료"
    done
    
    # 최종 보고서 생성
    generate_final_report "$test_dir"
    
    log_info "모든 테스트 완료!"
}

# 메인 함수
main() {
    # 테스트 유형 확인 (ddos 또는 portscan)
    TEST_TYPE=${1:-"ddos"}
    
    if [[ "$TEST_TYPE" != "ddos" && "$TEST_TYPE" != "portscan" ]]; then
        log_error "지원되지 않는 테스트 유형: $TEST_TYPE"
        log_info "사용법: $0 [ddos|portscan]"
        exit 1
    fi
    
    # 시작 메시지
    log_start "컨테이너 벤치마크 시작: Suricata vs SecuXFlow ($TEST_TYPE)"
    
    # 사전 요구사항 확인
    check_prerequisites
    
    # 테스트 디렉토리 생성
    test_dir=$(create_test_dirs)
    
    # 테스트 구성 저장
    cat > "${test_dir}/test_config.txt" << EOF
테스트 유형: $TEST_TYPE
테스트 시간: $(date)
테스트 지속 시간: $DURATION 초
테스트 반복 횟수: $TEST_REPEAT
네트워크 인터페이스: $INTERFACE
대상 IP: $TARGET_IP
DDoS 대역폭: $BANDWIDTH Mbps
EOF
    
    # 테스트 실행
    run_test_loop "$test_dir"
    
    # 종료 메시지
    log_start "벤치마크 완료!"
    log_info "결과 디렉토리: $test_dir"
}

# 스크립트 실행
main "$@"
