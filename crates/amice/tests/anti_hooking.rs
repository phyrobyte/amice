//! Integration tests for the AntiHooking prologue pass across C, Rust, and multiple targets.

mod common;

use common::{
    ObfuscationConfig, RustCompileBuilder, clang_compiler_path, detect_llvm_config, ensure_plugin_built,
    llvm_tool_path, output_dir, output_with_watchdog, plugin_path, rust_fixture_project_path,
};
use serial_test::serial;
use std::fs;
use std::process::Command;

#[test]
#[serial]
fn test_anti_hooking_c_binary_executes() {
    ensure_plugin_built();
    let dir = output_dir().join("anti_hooking_c");
    fs::create_dir_all(&dir).unwrap();
    let src = dir.join("sample.c");
    let bin = dir.join("sample_bin");
    fs::write(
        &src,
        r#"#include <stdio.h>
__attribute__((noinline))
int guarded_calc(int a, int b) { return (a * 3) ^ (b + 7); }
int main(void) {
    int v = guarded_calc(11, 5);
    printf("GUARDED=%d\n", v);
    return (v == ((11 * 3) ^ (5 + 7))) ? 0 : 1;
}
"#,
    )
    .unwrap();

    let mut cmd = Command::new(clang_compiler_path(false));
    cmd.arg("-O2")
        .arg(format!("-fpass-plugin={}", plugin_path().display()))
        .arg(&src)
        .arg("-o")
        .arg(&bin);
    let mut cfg = ObfuscationConfig::disabled();
    cfg.anti_hooking = Some(true);
    cfg.apply_to_command(&mut cmd);

    let compile_out = output_with_watchdog(cmd);
    assert!(
        compile_out.status.success(),
        "clang compile failed:\n{}",
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let run_out = output_with_watchdog(Command::new(&bin));
    assert!(run_out.status.success(), "compiled binary failed");
    assert!(String::from_utf8_lossy(&run_out.stdout).contains("GUARDED=45"));
}

#[test]
#[serial]
fn test_anti_hooking_emits_arm64_and_x86_64_prologue_ir() {
    ensure_plugin_built();
    let dir = output_dir().join("anti_hooking_ir");
    fs::create_dir_all(&dir).unwrap();
    let llvm_cfg = detect_llvm_config().expect("LLVM prefix required for opt check");
    let opt = llvm_tool_path(&llvm_cfg.prefix, "opt");

    for (triple, expected_snippet) in [
        (
            "aarch64-apple-darwin",
            "prologue <16 x i8> <i8 -15, i8 3, i8 17, i8 -86,",
        ),
        (
            "x86_64-pc-windows-msvc",
            "prologue <16 x i8> <i8 77, i8 -119, i8 -46, i8 77,",
        ),
        (
            "x86_64-unknown-linux-gnu",
            "prologue <16 x i8> <i8 77, i8 -119, i8 -46, i8 77,",
        ),
    ] {
        let input = dir.join(format!("{triple}.ll"));
        let output = dir.join(format!("{triple}.out.ll"));
        fs::write(
            &input,
            format!(
                "target triple = \"{triple}\"\n\
                 define i32 @probe(i32 %x) {{\n  %r = add i32 %x, 5\n  ret i32 %r\n}}\n"
            ),
        )
        .unwrap();

        let mut cmd = Command::new(&opt);
        cmd.arg(format!("--load-pass-plugin={}", plugin_path().display()))
            .arg("-passes=default<O2>")
            .arg("-S")
            .arg(&input)
            .arg("-o")
            .arg(&output);
        let mut cfg = ObfuscationConfig::disabled();
        cfg.anti_hooking = Some(true);
        cfg.apply_to_command(&mut cmd);

        let out = output_with_watchdog(cmd);
        assert!(
            out.status.success(),
            "opt failed for {triple}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let ir = fs::read_to_string(&output).unwrap();
        assert!(
            ir.contains(expected_snippet),
            "expected prologue snippet `{expected_snippet}` for {triple} in:\n{ir}"
        );
    }
}

#[test]
#[serial]
fn test_anti_hooking_rust_executes() {
    ensure_plugin_built();
    let project_dir = rust_fixture_project_path("flatten");
    let mut cfg = ObfuscationConfig::disabled();
    cfg.anti_hooking = Some(true);
    cfg.flatten = Some(true);

    let result = RustCompileBuilder::new(&project_dir, "flatten_test")
        .config(cfg)
        .compile();
    result.assert_success();
    let run_result = result.run();
    run_result.assert_success();
    assert!(run_result.stdout().contains("SUCCESS: All flatten tests passed!"));
}
