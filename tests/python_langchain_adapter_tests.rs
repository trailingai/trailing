use std::{env, path::PathBuf, process::Command};

#[test]
fn python_langchain_adapter_tests_pass() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let tests_dir = repo_root.join("sdk/python/tests");
    let python_path = repo_root.join("sdk/python");

    let mut combined_python_path = python_path.into_os_string();
    if let Some(existing) = env::var_os("PYTHONPATH") {
        combined_python_path.push(":");
        combined_python_path.push(existing);
    }

    let output = Command::new("python3")
        .args(["-m", "unittest", "discover", "-s"])
        .arg(&tests_dir)
        .args(["-p", "test_*.py"])
        .env("PYTHONPATH", combined_python_path)
        .output()
        .expect("failed to run python langchain adapter tests");

    assert!(
        output.status.success(),
        "python langchain adapter tests failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
