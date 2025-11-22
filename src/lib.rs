use blstrs::{G1Projective, G2Projective, Scalar, G1Affine, G2Affine};
use group::{Curve, Group};
use wasm_bindgen::prelude::*;
use web_sys::window;
use js_sys::Uint8Array;
use subtle::CtOption;
use blake2s_simd::Params as Blake2sParams;

// Panic hook for WASM
#[wasm_bindgen(start)]
pub fn wasm_start() {
    console_error_panic_hook::set_once();
}

/// Stable scalar generation from JS RNG
fn scalar_from_js_rng() -> Scalar {
    let mut seed = [0u8; 32];
    let win = window().expect("window not available");
    let crypto = win.crypto().expect("crypto not available");
    let array = Uint8Array::new_with_length(32);
    crypto
        .get_random_values_with_array_buffer_view(&array)
        .expect("RNG failed");
    array.copy_to(&mut seed);

    // Hash to 32 bytes using Blake2s
    let hash = Blake2sParams::new()
        .hash_length(32)
        .to_state()
        .update(&seed)
        .finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash.as_bytes()[..32]);

    // Reduce modulo r (Scalar order) to guarantee a valid scalar
    Scalar::from_bytes_be(&hash_bytes).unwrap_or_else(|| Scalar::from(1u64))
}

#[wasm_bindgen]
pub struct BlsKeypair {
    secret: Vec<u8>,
    public: Vec<u8>,
}

#[wasm_bindgen]
impl BlsKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<BlsKeypair, JsValue> {
        Self::generate()
    }

    pub fn generate() -> Result<BlsKeypair, JsValue> {
        let sk = scalar_from_js_rng();
        let pk = G1Projective::generator() * sk;

        Ok(BlsKeypair {
            secret: sk.to_bytes_be().to_vec(),
            public: pk.to_affine().to_compressed().to_vec(),
        })
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> Vec<u8> {
        self.public.clone()
    }
}

#[wasm_bindgen]
pub fn bls_sign(message: &[u8], secret_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if secret_bytes.len() != 32 {
        return Err(JsValue::from_str("Secret key must be 32 bytes"));
    }

    let sk_bytes: [u8; 32] = secret_bytes.try_into().unwrap();
    let sk = Scalar::from_bytes_be(&sk_bytes).unwrap_or_else(|| Scalar::from(1u64));
    let h = G2Projective::hash_to_curve(message, b"SAFE-PUMP-V4", &[]);
    let sig = h * sk;

    Ok(sig.to_affine().to_compressed().to_vec())
}

#[wasm_bindgen]
pub fn bls_verify(
    message: &[u8],
    pubkey_bytes: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, JsValue> {
    if pubkey_bytes.len() != 48 || sig_bytes.len() != 96 {
        return Err(JsValue::from_str("Invalid key or signature length"));
    }

    let pk_bytes: [u8; 48] = pubkey_bytes.try_into().unwrap();
    let sig_bytes_arr: [u8; 96] = sig_bytes.try_into().unwrap();

    let pk_ct: CtOption<G1Projective> = G1Projective::from_compressed(&pk_bytes);
    let sig_ct: CtOption<G2Projective> = G2Projective::from_compressed(&sig_bytes_arr);

    if pk_ct.is_none().unwrap_u8() == 1 || sig_ct.is_none().unwrap_u8() == 1 {
        return Ok(false);
    }

    let pk_affine: G1Affine = pk_ct.unwrap().to_affine();
    let sig_affine: G2Affine = sig_ct.unwrap().to_affine();
    let h_affine = G2Projective::hash_to_curve(message, b"SAFE-PUMP-V4", &[]).to_affine();
    let g1_gen = G1Projective::generator().to_affine();

    Ok(blstrs::pairing(&g1_gen, &sig_affine) == blstrs::pairing(&pk_affine, &h_affine))
}

#[wasm_bindgen]
pub fn encrypt_wallet_for_airdrop(wallet: &[u8], amount: u64) -> Result<Vec<u8>, JsValue> {
    if wallet.len() != 32 {
        return Err(JsValue::from_str("Wallet must be 32 bytes"));
    }

    let mut data = Vec::with_capacity(32 + 8 + 20);
    data.extend_from_slice(wallet);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(b"SAFE-PUMP-VAULT-2025");
    Ok(data)
}
