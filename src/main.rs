use noir_rsa_optimised::{hashmap_to_toml, generate_random_inputs};

fn main() {
    let hashmap = generate_random_inputs("hello world", 2048);
    println!("{:?}", hashmap_to_toml(hashmap));   
}
