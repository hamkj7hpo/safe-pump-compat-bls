/* tslint:disable */
/* eslint-disable */
export function bls_sign(message: Uint8Array, secret_bytes: Uint8Array): BlsSignature;
export function bls_verify(message: Uint8Array, pubkey_bytes: Uint8Array, sig_bytes: Uint8Array): boolean;
export function isolate_bls(): void;
export class BlsKeypair {
  free(): void;
  [Symbol.dispose](): void;
  constructor();
  static generate(): BlsKeypair;
  readonly public: Uint8Array;
  readonly secret: Uint8Array;
}
export class BlsSignature {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  readonly sig: Uint8Array;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_blskeypair_free: (a: number, b: number) => void;
  readonly __wbg_blssignature_free: (a: number, b: number) => void;
  readonly bls_sign: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly bls_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
  readonly blskeypair_generate: () => number;
  readonly blskeypair_public: (a: number) => [number, number];
  readonly blskeypair_secret: (a: number) => [number, number];
  readonly blssignature_sig: (a: number) => [number, number];
  readonly isolate_bls: () => void;
  readonly blskeypair_new: () => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
