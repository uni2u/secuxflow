#!/bin/bash
# scripts/build_rust_wasm.sh
echo "Building Rust WASM module..."
cd mcp_inspector
cargo build --target wasm32-wasi --release
cd ..

echo "Copying to wasm_modules directory..."
mkdir -p wasm_modules
cp mcp_inspector/target/wasm32-wasi/release/mcp_inspector.wasm wasm_modules/
echo "Done!"
