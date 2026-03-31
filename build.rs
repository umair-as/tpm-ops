// Embed git revision at compile time for deployment traceability
fn main() {
    // Git short hash — falls back gracefully if not in a git repo (e.g. Yocto fetch)
    let git_hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=TPM_OPS_GIT_HASH={}", git_hash);

    // Rebuild when HEAD moves across commits, including branch ref and packed refs.
    if let Some(git_dir) = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    {
        println!("cargo:rerun-if-changed={}/HEAD", git_dir);
        println!("cargo:rerun-if-changed={}/refs/heads", git_dir);
        println!("cargo:rerun-if-changed={}/packed-refs", git_dir);
    } else {
        println!("cargo:rerun-if-changed=.git/HEAD");
        println!("cargo:rerun-if-changed=.git/refs/heads");
        println!("cargo:rerun-if-changed=.git/packed-refs");
    }
}
