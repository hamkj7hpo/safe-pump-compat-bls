use blstrs::{G1Projective, G2Projective, pairing};
use group::{Group, Curve};  // <-- ADD Curve HERE
use group::ff::{Field, PrimeField};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

// Console log
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
pub struct BlsKeypair {
    secret: Vec<u8>,
    public: Vec<u8>,
}

#[wasm_bindgen]
impl BlsKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::generate()
    }

    #[wasm_bindgen]
    pub fn generate() -> BlsKeypair {
        let sk = blstrs::Scalar::random(&mut OsRng);
        let pk = G1Projective::generator() * sk;

        BlsKeypair {
            secret: sk.to_bytes_be().to_vec(),
            public: pk.to_compressed().to_vec(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> { self.secret.clone() }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> Vec<u8> { self.public.clone() }
}

#[wasm_bindgen]
pub struct BlsSignature {
    sig: Vec<u8>,
}

#[wasm_bindgen]
impl BlsSignature {
    #[wasm_bindgen(getter)]
    pub fn sig(&self) -> Vec<u8> { self.sig.clone() }
}

#[wasm_bindgen]
pub fn bls_sign(message: &[u8], secret_bytes: &[u8]) -> Result<BlsSignature, JsValue> {
    let sk_bytes: [u8; 32] = secret_bytes.try_into()
        .map_err(|_| JsValue::from_str("Secret key must be 32 bytes"))?;

    let sk = blstrs::Scalar::from_repr_vartime(sk_bytes)
        .ok_or_else(|| JsValue::from_str("Invalid scalar"))?;

    let h = G2Projective::hash_to_curve(message, b"SAFE-PUMP-V4", &[]);
    let sig = h * sk;

    Ok(BlsSignature {
        sig: sig.to_compressed().to_vec(),
    })
}

#[wasm_bindgen]
pub fn bls_verify(message: &[u8], pubkey_bytes: &[u8], sig_bytes: &[u8]) -> bool {
    let pk_bytes: [u8; 48] = match pubkey_bytes.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let sig_bytes: [u8; 96] = match sig_bytes.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let pk = G1Projective::from_compressed(&pk_bytes);
    if pk.is_some().unwrap_u8() == 0 { return false; }
    let pk = pk.unwrap();

    let sig = G2Projective::from_compressed(&sig_bytes);
    if sig.is_some().unwrap_u8() == 0 { return false; }
    let sig = sig.unwrap();

    let h = G2Projective::hash_to_curve(message, b"SAFE-PUMP-V4", &[]);

    let g1_affine = G1Projective::generator().to_affine();
    let sig_affine = sig.to_affine();
    let pk_affine = pk.to_affine();
    let h_affine = h.to_affine();

    let left = pairing(&g1_affine, &sig_affine);
    let right = pairing(&pk_affine, &h_affine);

    left == right
}

#[wasm_bindgen]
pub fn isolate_bls() {
    console_log!("WarpCore V4: BLS isolation online. Multi-chain ready.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_roundtrip() {
        let msg = b"SafePump test message";
        let kp = BlsKeypair::generate();
        let sig = bls_sign(msg, &kp.secret).unwrap();
        assert!(bls_verify(msg, &kp.public, &sig.sig));
    }
}
