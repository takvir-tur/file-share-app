fn main() {
    println!("cargo:rerun-if-changed=macos-share-extension");
    tauri_build::build()
}

