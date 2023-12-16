use std::collections::HashMap;
use num_bigint::{BigUint, ToBigInt, Sign};
use num_traits::{One, Zero};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::{SigningKey, VerifyingKey, Signature};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::sha2::{Digest, Sha256};
use rsa::traits::PublicKeyParts;

fn sign_with_rsa(msg: &str) -> (RsaPublicKey, Signature) {
    let mut rng = rand::thread_rng();

    let bits = 4096;
    let private_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = private_key.to_public_key();
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let verifying_key: VerifyingKey<Sha256> = signing_key.verifying_key();
    
    // Sign
    let data = msg.as_bytes();
    let signature = signing_key.sign_with_rng(&mut rng, data);
    assert_ne!(signature.to_bytes().as_ref(), data);
    
    // Verify
    verifying_key.verify(data, &signature).expect("failed to verify");

    (public_key, signature)
}

// Converts a byte slice to a vector of hexadecimal strings
fn bytes_to_hex_array(bstr: &[u8]) -> Vec<String> {
    bstr.iter().map(|&b| format!("0x{:02x}", b)).collect()
}

// Converts a hexadecimal string to a format suitable for Noir array
fn hex_to_noir_array(s: &str) -> String {
    let bytes = hex::decode(&s[2..]).expect("Invalid hex string");
    let hex_repr = bytes_to_hex_array(&bytes);
    let mut formatted = String::new();
    for (i, hex) in hex_repr.iter().enumerate() {
        formatted.push_str(hex);
        if i % 16 == 15 {
            formatted.push_str(",\n\t");
        } else {
            formatted.push_str(", ");
        }
    }
    formatted
}

// Prints a byte array as a Noir array
fn print_hex_as_noir_array(name: &str, s: &str) {
    let hex_repr = hex_to_noir_array(s);
    let mut bytes: Vec<u8>;
    if s.len() % 2 != 0 {
        bytes = hex::decode(format!("0{}", &s[2..])).expect("Invalid hex string");
    } else {
        bytes = hex::decode(&s[2..]).expect("Invalid hex string");
    }
    println!("let {}: [u8; {}] = [\n\t{}];\n", name, bytes.len(), hex_repr);
}

// Converts an object to a TOML string
fn obj_to_toml(obj: HashMap<&str, Vec<u8>>) -> String {
    let mut toml = String::new();
    for (k, v) in obj {
        if let Ok(v_str) = String::from_utf8(v.clone()) {
            toml += &format!("{} = \"{}\"\n", k, v_str);
        } else {
            let b_array: Vec<String> = v.iter().map(|&b| b.to_string()).collect();
            toml += &format!("{} = [{}]\n", k, b_array.join(", "));
        }
    }
    toml
}
 
fn get_final_e(sig: BigUint, pubkey: BigUint) -> BigUint {
    let mut final_e = sig;
    for _ in 0..16 {
        final_e = &final_e * &final_e % &pubkey;
    }
    final_e
}

fn get_sig_quotient(sig: BigUint, pubkey: BigUint, final_e: BigUint) -> BigUint {
    let dividend = sig * final_e;
    let sig_quotient = dividend / pubkey;
    sig_quotient
}

// RSA modular exponentiation
fn rsa_mod_exp(base: BigUint, exponent: BigUint, modulus: BigUint) -> BigUint {
    let mut result = BigUint::one();
    let mut base = base % &modulus;
    let mut exponent = exponent;

    while exponent > BigUint::zero() {
        if &exponent % BigUint::from(2 as u8) == BigUint::one() {
            result = (result * &base) % &modulus;
        }
        exponent = exponent >> 1;
        base = (&base * &base) % &modulus;
    }

    result
}

fn main() {
    let msg: &str = "Hello world!";
    let (public_key, signature) = sign_with_rsa(&msg);
    let converted_signature = BigUint::from_bytes_be(&signature.to_bytes());
    let converted_modulus = BigUint::from_bytes_be(&public_key.n().to_bytes_be());

    let final_e = get_final_e(converted_signature.clone(), converted_modulus.clone());
    println!("final_e: {:?}", final_e.to_str_radix(16));
    let quotient = get_sig_quotient(converted_signature.clone(), converted_modulus.clone(), final_e.clone());
    println!("quotient: {:?}", quotient.to_str_radix(16));

    print_hex_as_noir_array("sig_bytes", &signature.to_string());
    print_hex_as_noir_array("pubkey_bytes", &public_key.n().to_str_radix(16));
    print_hex_as_noir_array("final_e_bytes", &final_e.to_str_radix(16));
    print_hex_as_noir_array("quotient_bytes",  &quotient.to_str_radix(16));
    
    let hash = sha256::digest(msg);

    let msg_hash_bytes = hex::decode(hash).expect("Invalid hex string");

    let mut hashmap: HashMap<&str, Vec<u8>> = HashMap::new();
    hashmap.insert("sig", signature.to_bytes().into());
    hashmap.insert("pubkey", public_key.n().to_bytes_be().into());
    hashmap.insert("final_e", final_e.to_bytes_be().into());
    hashmap.insert("quotient", quotient.to_bytes_be().into());
    hashmap.insert("msg_hash",   msg_hash_bytes.into());
    println!("{:?}", obj_to_toml(hashmap));
    
}
