/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const init: () => void;
export const precompute: (a: number, b: number) => [number, number, number];
export const precompute_from_witness: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
export const precompute_show_from_witness: (a: number, b: number, c: number, d: number) => [number, number, number];
export const present: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number];
export const setup: () => [number, number, number];
export const setup_prepare: () => [number, number, number];
export const setup_show: () => [number, number, number];
export const verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number];
export const verify_single: (a: number, b: number, c: number, d: number) => [number, number, number];
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_start: () => void;
