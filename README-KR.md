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
sudo apt update && sudo apt install -y build-essential llvm clang libelf-dev zlib1g-dev bpftool linux-headers-$(uname -r) wabt
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
엔진은 `INSPECT_K` 환경 변수를 통해 검사 깊이($k$값)를 동적으로 조절합니다.

#### A. 인프라 성능 및 자원 효율성 (Table 1, Fig 2)
- 목표: 5 Gbps Baseline 부하 상황에서의 안정성 및 자원 효율성 측정.
- 실행:

```bash
sudo INSPECT_K=12 WASM_MODULE=wasm_modules/mcp_inspector.wasm ./target/release/secuxflow --iface <NIC_NAME>
```

- 데이터 확인: `benchmark_results/` 내 생성된 CSV의 `cpu_usage_pct`와 `rx_kbps` 확인.

#### B. 보안 정확도 및 지연 시간 모델 (Fig 3, Table 2)
- 목표: $k$값 변화에 따른 탐지율(Accuracy)과 지연 시간($E[L]$)의 상관관계 증명.
- 실행: `INSPECT_K`값을 1, 4, 8, 12, 16, 20으로 가변 적용하여 반복 테스트 수행.

```bash
sudo INSPECT_K=<VALUE> ./target/release/secuxflow --iface <NIC_NAME>
# 다른 터미널에서 MCP 공격 트래픽 주입
sudo python3 scripts/mcp_generator.py --iface <NIC_NAME> --dst-ip <TARGET_IP>
```

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
