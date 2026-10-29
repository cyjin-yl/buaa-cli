use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::symm::{Cipher, encrypt};
use serde_json::json;

fn decode(plaintext: &[u8]) -> serde_json::Value {
    let key = *b"synthetic-key-16";
    let ciphertext = encrypt(Cipher::aes_128_ecb(), &key, None, plaintext).unwrap();
    let wire = STANDARD.encode(ciphertext);
    buaa_cli::boya::decode_response(wire.as_bytes(), Some("text/plain"), &key)
}

#[test]
fn null_token_allows_a_normal_encrypted_response() {
    let value = decode(br#"{"status":"0","token":null,"data":{"id":101,"title":"synthetic"}}"#);
    assert_eq!(value["result"], "success");
    assert_eq!(value["data"], json!({"id":101,"title":"synthetic"}));

    let escaped = decode(br#"{"status":"0","\u0074oken":null,"data":{"id":102}}"#);
    assert_eq!(escaped["result"], "success");
    assert_eq!(escaped["data"], json!({"id":102}));
}

#[test]
fn real_token_values_remain_withheld() {
    for input in [
        br#"{"status":"0","token":"synthetic-private","data":{"id":101}}"#.as_slice(),
        br#"{"status":"0","data":{"\u0074oken":"synthetic-private"}}"#.as_slice(),
        br#"{"status":"0","token":"null","data":{"id":101}}"#.as_slice(),
        br#"{"status":"0","access_token":null,"data":{"id":101}}"#.as_slice(),
        br#"{"status":"0","token":null,"data":{"access_token":"synthetic-private"}}"#.as_slice(),
    ] {
        let value = decode(input);
        assert_ne!(value["result"], "success");
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("synthetic-private"));
    }
}
