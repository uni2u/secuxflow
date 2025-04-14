use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "bpf/xdp_filter.c";

fn main() {
    // BPF 프로그램이 변경되면 빌드를 다시 수행하도록 설정
    println!("cargo:rerun-if-changed={}", SRC);

    // libbpf-cargo를 사용하여 BPF 프로그램 빌드
    let result = SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate("./src/xdp_filter.skel.rs");

    // 개발 환경에서는 BPF 프로그램이 없을 수 있으므로, 
    // 빌드 실패시 빈 스켈레톤 파일 생성
    if let Err(err) = result {
        println!("cargo:warning=Failed to build BPF program: {}", err);
        
        // 타겟 디렉토리에 빈 스켈레톤 파일 생성
        let out_dir = PathBuf::from("./src");
        let dest_path = out_dir.join("xdp_filter.skel.rs");
        
        std::fs::write(
            &dest_path,
            r#"
// 개발 환경용 빈 스켈레톤
#[allow(dead_code)]
pub struct XdpFilterSkelBuilder;

#[allow(dead_code)]
impl XdpFilterSkelBuilder {
    pub fn new() -> Self { Self }
    pub fn open(self) -> Result<XdpFilterSkel, libbpf_rs::Error> {
        Err(libbpf_rs::Error::System(libc::ENOSYS))
    }
}

#[allow(dead_code)]
pub struct XdpFilterSkel;

#[allow(dead_code)]
impl XdpFilterSkel {
    pub fn progs(&self) -> XdpFilterProgs { XdpFilterProgs }
    pub fn maps(&self) -> XdpFilterMaps { XdpFilterMaps }
    pub fn attach(&mut self) -> Result<(), libbpf_rs::Error> {
        Err(libbpf_rs::Error::System(libc::ENOSYS))
    }
}

#[allow(dead_code)]
pub struct XdpFilterProgs;
#[allow(dead_code)]
pub struct XdpFilterMaps;
"#,
        ).expect("Failed to write empty skeleton file");
    }
}
