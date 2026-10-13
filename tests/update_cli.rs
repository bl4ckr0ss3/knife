use std::process::Command;

#[test]
fn update_is_a_real_subcommand_with_read_only_check() {
    let output = Command::new(env!("CARGO_BIN_EXE_knife"))
        .args(["update", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("knife update"));
    assert!(text.contains("--check"));
    assert!(text.contains("--json"));
}
