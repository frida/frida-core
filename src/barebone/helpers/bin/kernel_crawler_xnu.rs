#[no_mangle]
pub extern "C" fn crawl(x: i32) -> i32 {
    println!("yay x={x}");
    42
}
