#[test]
fn zz_dump_fixture_again() {
    let buf = reknife::formats::fixture::pe_with_driver();
    let out = std::env::temp_dir().join("knifelab.sys");
    std::fs::write(&out, &buf).unwrap();
}
