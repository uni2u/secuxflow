# SecuXFlow (실험 재현 가이드)

SecuXFlow는 eBPF-XDP 기반의 고속 패킷 필터링과 WASM 모듈을 활용한 지능형 L7 검사를 결합한 차세대 네트워크 보안 시스템의 PoC(Proof-of-Concept)입니다. 본 프로젝트는 클라우드 네이티브 및 분산 환경, 특히 AI 학습 클러스터와 같은 대규모 워크로드 환경에서의 네트워크 최적화와 보안을 목표로 합니다.

## 🚀 Research Replication Guide

본 가이드는 논문의 핵심 데이터(Fig 2, 3, Table 1, 2)를 테스트베드에서 재현하기 위한 오프라인 전용 절차를 설명합니다.

### 1. 오프라인 환경 준비 (이동 전 필수 작업)
테스트베드(오프라인)로 이동하기 전, 외부 네트워크가 연결된 상태에서 다음 명령을 통해 모든 의존성을 로컬 환경에 캐싱하십시오.

```bash
# Rust 의존성 라이브러리 로컬 캐싱
cargo fetch

# 필요한 Docker 이미지 및 패키지 미리 다운로드
sudo docker pull jasonish/suricata:latest
sudo docker pull ubuntu:22.04

# Ubuntu 패키지 미리 설치
sudo apt update && sudo apt install -y build-essential llvm clang libbpf-dev libelf-dev zlib1g-dev bpftool linux-headers-$(uname -r) wabt
```

### 2. 빌드 절차 (Build Process)
현장 리눅스 환경에서 다음 순서로 빌드를 진행합니다.

```bash
# 1. L7 MCP Inspector (WASM) 빌드
./scripts/build_rust_wasm.sh

# 2. SecuXFlow 메인 엔진 빌드 (BPF 스켈레톤 자동 생성 포함)
cargo build --release
```

### 3. 실험별 실행 및 제어 (Experiment Control)
아래의 실험 A(성능 비교)와 실험 B(MCP 검증)는 **동일 엔진을 사용하는 별도 시나리오**이며, 한 번에 섞어서 수행하지 않습니다.
엔진은 `INSPECT_K` 환경 변수를 통해 검사 깊이($k$값)를 동적으로 조절합니다.

#### A. 인프라 성능 및 자원 효율성 (Table 1, Fig 2, Suricata 비교 파트)
- 목표: 5 Gbps Baseline 부하 상황에서의 안정성 및 자원 효율성 측정.
- 실행:

```bash
sudo INSPECT_K=12 WASM_MODULE=wasm_modules/mcp_inspector.wasm ./target/release/secuxflow --iface <NIC_NAME> run
```

- 위 명령은 엔진을 상주 실행하는 용도입니다. `Ctrl+C`로 종료합니다.
- `benchmark.sh` 및 `container_benchmark.sh`는 `SECUXFLOW_METRICS_FILE` 환경변수로 각 실행 디렉토리 안의 `metrics_secuxflow.csv`를 생성합니다.
- 데이터 확인: `metrics_secuxflow.csv`의 `cpu_usage_pct`, `rx_kbps`, `memory_rss_kb` 열 확인.

#### B. 보안 정확도 및 지연 시간 모델 (Fig 3, Table 2, MCP 검증 파트)
- 목표: $k$값 변화에 따른 탐지율(Accuracy)과 지연 시간($E[L]$)의 상관관계 증명.
- 실행: `INSPECT_K`값을 1, 4, 8, 12, 16, 20으로 가변 적용하여 반복 테스트 수행.
- 본 실험은 Suricata 비교 파트와 분리해서 수행하며, 엔진 구동 후 **다른 터미널에서** MCP 트래픽을 주입합니다.

```bash
sudo INSPECT_K=<VALUE> ./target/release/secuxflow --iface <NIC_NAME> run
```

```bash
# 다른 터미널에서 MCP 공격 트래픽 주입
sudo python3 scripts/mcp_generator.py --iface <NIC_NAME> --dst-ip <TARGET_IP>
```

##### 실험 B 최소 계측 절차
실험 B는 generator 기반 synthetic MCP-like traffic을 사용하며, 실시간 탐지율 및 검사 지연 시간은 엔진 로그와 generator trace를 수동 대조하여 검증합니다.

```bash
# 터미널 1: 엔진 실행 (실험 B 계측 로그 포함)
sudo SECUXFLOW_INSPECT_LOG_FILE=benchmark_results/experiment_b_inspection.csv \
INSPECT_K=<VALUE> WASM_MODULE=wasm_modules/mcp_inspector.wasm \
./target/release/secuxflow --iface <NIC_NAME> run

# 터미널 2: generator 실행 (송신 trace 저장)
sudo python3 scripts/mcp_generator.py \
  --iface <NIC_NAME> \
  --dst-ip <TARGET_IP> \
  --trace-file benchmark_results/mcp_generator_trace.csv
```

- 실험 종료후 다음의 파일 확인
```bash
benchmark_results/mcp_generator_trace.csv
benchmark_results/experiment_b_inspection.csv
```

#### 수동 검증 방법
```md id="2vrz7b"
##### 실시간 탐지율 수동 검증
generator trace의 `label`을 ground truth로 사용하고, inspection 로그의 `verdict`를 기준으로 탐지 여부를 판단합니다.

```bash
# generator가 전송한 malicious 샘플 수
awk -F',' 'NR>1 && $2=="malicious" {c++} END {print c+0}' benchmark_results/mcp_generator_trace.csv

# inspection 로그에서 malicious 샘플 중 탐지된 수 (DROP 또는 ALERT)
awk -F',' 'NR>1 && $5=="malicious" && ($7 ~ /^DROP/ || $7 ~ /^ALERT/) {c++} END {print c+0}' benchmark_results/experiment_b_inspection.csv

# 단순 탐지율(%)
awk 'BEGIN { sent=0; detected=0 }
     FNR==NR && NR>1 { if ($2=="malicious") sent++ ; next }
     NR>1 { if ($5=="malicious" && ($7 ~ /^DROP/ || $7 ~ /^ALERT/)) detected++ }
     END {
       if (sent>0) printf "Detection Rate: %.2f%%\\n", (detected/sent)*100;
       else print "Detection Rate: N/A";
     }' FS=',' benchmark_results/mcp_generator_trace.csv benchmark_results/experiment_b_inspection.csv
```

#### 검사 지연 시간 수동 검증
inspection 로그의 `latency_ns` 열을 기준으로 평균 및 최대 검사 지연 시간을 계산합니다.

```bash
# 평균 검사 지연 시간(ns)
awk -F',' 'NR>1 {sum+=$3; n++} END { if (n>0) printf "Mean Latency(ns): %.2f\\n", sum/n; else print "Mean Latency(ns): N/A" }' benchmark_results/experiment_b_inspection.csv

# 최대 검사 지연 시간(ns)
awk -F',' 'NR>1 { if ($3>max) max=$3 } END { if (max>0) printf "Max Latency(ns): %d\\n", max; else print "Max Latency(ns): N/A" }' benchmark_results/experiment_b_inspection.csv

# p95 검사 지연 시간(ns)
awk -F',' 'NR>1 {print $3}' benchmark_results/experiment_b_inspection.csv | sort -n | \
awk '{
  a[NR]=$1
}
END {
  if (NR==0) { print "P95 Latency(ns): N/A"; exit }
  idx=int(NR*0.95)
  if (idx<1) idx=1
  printf "P95 Latency(ns): %s\\n", a[idx]
}'
```

#### 해석기준
위 수동 검증 블록 **바로 아래**에 아래 설명을 넣어 주세요.

```md id="4yaj21"
##### 해석 기준 및 주의사항
- 본 실험은 실제 운영 트래픽이 아닌 **generator 기반 synthetic MCP-like traffic**을 사용합니다.
- `latency_ns`는 userspace가 inspect event를 수신한 시점(`recv_ts_ns`)부터 WASM 검사 완료 시점(`done_ts_ns`)까지의 차이입니다.
- 따라서 본 값은 **PoC 수준의 L7 검사 지연 시간**을 의미하며, 전체 네트워크 왕복 지연 시간(RTT)이나 제품 수준 end-to-end latency를 직접 의미하지 않습니다.
- `label=malicious` 샘플에 대해 `verdict`가 `DROP` 또는 `ALERT`이면 탐지된 것으로 간주합니다.
- `INSPECT_K`를 1, 4, 8, 12, 16, 20 등으로 변경하면서 탐지율과 검사 지연 시간의 trade-off를 비교합니다.


### 4. 데이터 지표 매핑 (Metric Mapping)
수집된 Raw 데이터와 논문 지표 간의 분석 방법입니다.

- Throughput: `metrics_secuxflow.csv` | `rx_kbps` 평균값 (Gbps 단위 변환)
- CPU Usage: `metrics_secuxflow.csv` | `cpu_usage_pct` 평균 (Suricata 비교군 대조)
- Detection Acc.: Console Stdout | `[WARN] Alert` 로그 발생 횟수 / 총 공격 패킷 수
- Early Exit: BPF Map Dump | `bpftool map dump` 결과의 카운트가 $k$에서 멈추는지 확인

### 시스템 아키텍처 및 구성
SecuXFlow는 커널 레벨의 XDP Filter와 고급 트래픽 검사를 수행하는 WASM Module로 구성됩니다.

- XDP Filter: eBPF를 사용하여 커널 레벨에서 고속 패킷 처리 및 Early Exit 수행.
- WASM Modules: 유연한 L7 페이로드 검사 제공.
- CLI Interface: 필터링 룰 및 시스템 설정 동적 관리.

### 시스템 요구 사항
- OS: Linux Kernel 5.4 이상 (5.15+ 권장).
- 의존성: `llvm`, `clang`, `libelf-dev`, `libbpf-dev`, `wabt`.

### 현장 트러블슈팅
- XDP 로드 실패: 커널 버전 미달 시 `xdpgeneric` 모드 사용 검토.
- WASM 실행 오류: `WASM_MODULE` 환경 변수 경로 확인.
- 권한 문제: 모든 작업에 `sudo` 권한 필요.
