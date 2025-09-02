use regex::Regex;

fn main() {
    let re = Regex::new(r"^\d+$").unwrap();
    let test_str = "123456";
    println!(
        "Does '{}' consist only of digits? {}",
        test_str,
        re.is_match(test_str)
    );
}
