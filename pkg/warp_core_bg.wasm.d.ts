/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const __wbg_blskeypair_free: (a: number, b: number) => void;
export const __wbg_blssignature_free: (a: number, b: number) => void;
export const bls_sign: (a: number, b: number, c: number, d: number) => [number, number, number];
export const bls_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
export const blskeypair_generate: () => number;
export const blskeypair_public: (a: number) => [number, number];
export const blskeypair_secret: (a: number) => [number, number];
export const blssignature_sig: (a: number) => [number, number];
export const isolate_bls: () => void;
export const blskeypair_new: () => number;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_start: () => void;
