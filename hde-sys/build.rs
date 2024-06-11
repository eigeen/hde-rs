fn main() {
    cc::Build::new()
        .file("src/hde/hde32.c")
        .file("src/hde/hde64.c")
        .compile("hde");
}
