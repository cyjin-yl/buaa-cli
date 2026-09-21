use base64::Engine as _;
use base64::alphabet::Alphabet;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use hmac::{Hmac, Mac};
use md5::Md5;
use serde::Serialize;
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

const ALPHABET: &str = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

pub(crate) struct LoginMaterial {
    pub info: String,
    pub hmd5: String,
    pub checksum: String,
}

#[derive(Serialize)]
struct Info<'a> {
    username: &'a str,
    password: &'a str,
    ip: &'a str,
    acid: u32,
    enc_ver: &'static str,
}

fn words(bytes: &[u8], include_size: bool) -> Vec<u32> {
    let mut output = Vec::with_capacity(bytes.len().div_ceil(4) + usize::from(include_size));
    for chunk in bytes.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        output.push(u32::from_le_bytes(word));
    }
    if include_size {
        output.push(bytes.len() as u32);
    }
    output
}

fn xencode(message: &[u8], key: &[u8]) -> Vec<u8> {
    if message.is_empty() {
        return Vec::new();
    }
    let mut values = words(message, true);
    let mut key = words(key, false);
    key.resize(4, 0);
    let length = values.len();
    let mut right = values[length - 1];
    let mut sum = 0u32;
    for _ in 0..(6 + 52 / length) {
        sum = sum.wrapping_add(0x9e37_79b9);
        let e = (sum >> 2) & 3;
        for index in 0..length {
            let left = values[(index + 1) % length];
            let mixed = ((right >> 5) ^ left.wrapping_shl(2))
                .wrapping_add((left >> 3) ^ right.wrapping_shl(4))
                ^ ((sum ^ left).wrapping_add(key[(index & 3) ^ e as usize] ^ right));
            right = values[index].wrapping_add(mixed);
            values[index] = right;
        }
    }
    values.into_iter().flat_map(u32::to_le_bytes).collect()
}

pub(crate) fn derive(
    username: &str,
    password: &str,
    ip: &str,
    acid: u32,
    token: &str,
) -> Result<LoginMaterial, ()> {
    let info_json = Zeroizing::new(
        serde_json::to_string(&Info {
            username,
            password,
            ip,
            acid,
            enc_ver: "srun_bx1",
        })
        .map_err(|_| ())?,
    );
    let engine = GeneralPurpose::new(
        &Alphabet::new(ALPHABET).map_err(|_| ())?,
        GeneralPurposeConfig::new(),
    );
    let info = format!(
        "{{SRBX1}}{}",
        engine.encode(xencode(info_json.as_bytes(), token.as_bytes()))
    );
    let mut hmac = Hmac::<Md5>::new_from_slice(token.as_bytes()).map_err(|_| ())?;
    hmac.update(password.as_bytes());
    let hmd5 = format!("{:x}", hmac.finalize().into_bytes());
    let checksum_input = Zeroizing::new(format!(
        "{token}{username}{token}{hmd5}{token}{acid}{token}{ip}{token}200{token}1{token}{info}"
    ));
    let checksum = format!("{:x}", Sha1::digest(checksum_input.as_bytes()));
    Ok(LoginMaterial {
        info,
        hmd5,
        checksum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_protocol_vector_matches_independent_implementation() {
        let material = derive(
            "student",
            "synthetic-secret",
            "10.0.0.2",
            62,
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(material.hmd5, "dba5ccebf5a5bf85ddee428f833a2b92");
        assert_eq!(
            material.checksum,
            "180a6a8f42990f46e34417d207d801fda0814e3b"
        );
        assert_eq!(
            material.info,
            "{SRBX1}dlPYdz+AOPp6xqRerQSP0b+xj0JIQWn55V8BU3BVUzYlEf/5PVqpeCUVdHWg68WR5nztmQU1QUVEGqpmXSyw/zb8Um6OVo92lhc2OxfIhbe52bJ5a5OJv7cp6TMpmXXK+g7//KkOee2="
        );
    }
}
