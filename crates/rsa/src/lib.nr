use dep::large_integer::{LargeInteger, MAX_BYTES};
use dep::std::println;

/**
* c.f. https://tools.ietf.org/html/rfc8017#section-9.2
* 1. For the six hash functions mentioned in Appendix B.1, the DER
* encoding T of the DigestInfo value is equal to the following:
* ...
* SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
*/
global SHA256_PADDING = [32, 4, 0, 5, 1, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 49, 48];

pub fn decrypt_rsa(
    sig: LargeInteger,  
    pubkey: LargeInteger,
    final_e: LargeInteger,
    sig_quotient: LargeInteger
) -> [u8; MAX_BYTES] {
    // To decrypt: (sig*final_e)-(pubkey*quotient)
    let dividend = sig.mul(final_e).0;
    let mul_result = pubkey.mul(sig_quotient).0;
    let sig_decrypted = dividend.sub(mul_result);
    let sig_decrypted_bytes: [u8; MAX_BYTES] = sig_decrypted.to_bytes();

    sig_decrypted_bytes
}

fn compare_signature_sha256<T>(
    padded_sha256_hash: [u8; MAX_BYTES],
    msg_hash: [u8; 32],
    sig: [u8; MAX_BYTES]
) -> bool {
    // Get length of sig (e.g. 1048 = 128 bytes, 2048 = 256 bytes)
    // NOTE: Assume MAX_BYTES < 2^32 bit number. MAX_BYTES of 259 > 2^8 bits so need to cast it to u32
    let mut sig_len = 0 as u32;
    let mut sum = 0 as u32;
    for i in 0..MAX_BYTES {
        sum += sig[MAX_BYTES - 1 - i] as u32;
        if sum == 0 {
            sig_len = MAX_BYTES as u32 - 1 - i as u32;
        }
    }

    for i in 0..32 {
        // Padded hash is reversed
        assert(padded_sha256_hash[31 - i] == msg_hash[i]);
    }

    for i in 32..51 {
        assert(SHA256_PADDING[i - 32] == padded_sha256_hash[i]);
    }

    assert(padded_sha256_hash[51] == 0);

    // Sub 32 bytes for hash, 19 bytes for prefix, 1 byte for 0, 1 byte for 1, 1 byte for 0
    let ps_len = sig_len - 54;
    for i in 52..MAX_BYTES {
        if i as u32 < 52 + ps_len as u32 {
            // PS padding which depends on RSA modulus / sig length. 1024 bits = 128 bytes = 128 - 54 = 74 bytes of 0xFF padding
            assert(padded_sha256_hash[i] == 255);
        } else if i as u32 == 52 + ps_len as u32 {
            // Pad 0x01
            assert(padded_sha256_hash[i] == 1);
        } else if i as u32 == 53 + ps_len as u32 {
            // 0x00
            assert(padded_sha256_hash[i] == 0);
        } else {
            // Padded with 0 until MAX_BYTES
            assert(padded_sha256_hash[i] == 0);
        }
    }

    true
}

pub fn verify_rsa_sha256_pkcs1v15(
    msg_hash: [u8; 32],
    sig: LargeInteger,
    pubkey: LargeInteger,
    final_e: LargeInteger,
    sig_quotient: LargeInteger
) -> bool {
    let sig_decrypted_bytes: [u8; MAX_BYTES] = decrypt_rsa(sig, pubkey, final_e, sig_quotient);
    compare_signature_sha256(sig_decrypted_bytes, msg_hash, sig.to_bytes())
}
