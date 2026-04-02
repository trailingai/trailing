use std::process::Command;

fn python_command() -> String {
    std::env::var("PYTHON").unwrap_or_else(|_| "python3".to_string())
}

#[test]
fn python_sdk_unit_tests_pass() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut python_paths = vec![std::path::PathBuf::from(format!(
        "{manifest_dir}/sdk/python"
    ))];
    if let Some(existing) = std::env::var_os("PYTHONPATH") {
        python_paths.extend(std::env::split_paths(&existing));
    }
    let python_path = std::env::join_paths(python_paths).expect("python path should build");

    let status = Command::new(python_command())
        .current_dir(manifest_dir)
        .env("PYTHONPATH", python_path)
        .args(["-m", "unittest", "discover", "-s", "sdk/python/tests", "-v"])
        .status()
        .expect("python test process should start");

    assert!(status.success(), "python sdk unit tests failed: {status}");
}
