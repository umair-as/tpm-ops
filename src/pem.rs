/// Encode a DER length field.
fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// Wrap content in a DER SEQUENCE.
fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encode a positive INTEGER (prepend 0x00 if high bit set).
fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x02];
    if !bytes.is_empty() && bytes[0] & 0x80 != 0 {
        out.extend_from_slice(&der_length(bytes.len() + 1));
        out.push(0x00);
    } else {
        out.extend_from_slice(&der_length(bytes.len()));
    }
    out.extend_from_slice(bytes);
    out
}

/// Encode RSA public key in PKCS#1 DER format (RSAPublicKey).
pub(crate) fn encode_rsa_pubkey_der(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut content = der_integer(modulus);
    content.extend_from_slice(&der_integer(exponent));
    der_sequence(&content)
}

/// Encode EC public key in SubjectPublicKeyInfo DER format (for P-256).
pub(crate) fn encode_ec_pubkey_der(uncompressed_point: &[u8]) -> Vec<u8> {
    // OID for id-ecPublicKey (1.2.840.10045.2.1)
    let ec_pubkey_oid: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    // OID for prime256v1 / P-256 (1.2.840.10045.3.1.7)
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    let mut algo_id = Vec::new();
    algo_id.extend_from_slice(ec_pubkey_oid);
    algo_id.extend_from_slice(p256_oid);
    let algo_seq = der_sequence(&algo_id);

    let mut bitstring = vec![0x03];
    bitstring.extend_from_slice(&der_length(uncompressed_point.len() + 1));
    bitstring.push(0x00);
    bitstring.extend_from_slice(uncompressed_point);

    let mut spki = Vec::new();
    spki.extend_from_slice(&algo_seq);
    spki.extend_from_slice(&bitstring);
    der_sequence(&spki)
}

/// Base64-encode DER bytes into PEM format.
pub(crate) fn der_to_pem(der: &[u8], label: &str) -> String {
    use std::fmt::Write;
    let b64 = base64_encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    write!(pem, "-----END {}-----", label).unwrap();
    pem
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}
