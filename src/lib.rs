use blstrs::{G1Projective, G2Projective, pairing};
use group::{Group, Curve};
use wasm_bindgen::prelude::*;
use web_sys::window;
use js_sys::Uint8Array;

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
        let mut seed = [0u8; 32];
        let win = window().expect("window");
        let crypto = win.crypto().expect("crypto");

        let array = Uint8Array::new_with_length(32);

        // Uint8Array IS an ArrayBufferView → pass directly!
        crypto.get_random_values_with_array_buffer_view(&array)
            .expect("RNG failed");

        array.copy_to(&mut seed);

        let sk = blstrs::Scalar::from_bytes_be(&seed)
            .unwrap();

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
pub fn bls_sign(message: &[u8], secret_bytes: &[u8]) -> BlsSignature {
    let sk_bytes: [u8; 32] = secret_bytes.try_into()
        .expect("Secret key must be 32 bytes");

    let sk = blstrs::Scalar::from_bytes_be(&sk_bytes)
        .unwrap();

    let h = G2Projective::hash_to_curve(message, b"SAFE-PUMP-V4", &[]);
    let sig = h * sk;

    BlsSignature {
        sig: sig.to_compressed().to_vec(),
    }
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
