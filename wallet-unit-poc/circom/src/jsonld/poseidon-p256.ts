import { POSEIDON_T3 } from "./poseidon-t3-constants.ts";

// The circuits run over secq256r1, whose scalar field is the P-256 base field.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;

const C = POSEIDON_T3.C.map((h) => BigInt("0x" + h));
const S = POSEIDON_T3.S.map((h) => BigInt("0x" + h));
const M = POSEIDON_T3.M.map((r) => r.map((h) => BigInt("0x" + h)));
const PM = POSEIDON_T3.P.map((r) => r.map((h) => BigInt("0x" + h)));

const T = 3;
const N_ROUNDS_F = 8;
const N_ROUNDS_P = 57;

const add = (a: bigint, b: bigint) => (a + b) % P;
const mul = (a: bigint, b: bigint) => (a * b) % P;
const pow5 = (a: bigint) => mul(a, mul(mul(a, a), mul(a, a)));

function mix(state: bigint[], m: bigint[][]): bigint[] {
  return state.map((_, i) => state.reduce((acc, a, j) => add(acc, mul(m[j][i], a)), 0n));
}

/**
 * circomlib Poseidon(2) over the secq256r1 field. Follows the optimized round
 * structure of circomlib's poseidon.circom exactly: its S and P constants were
 * derived over the BN254 field, so this is not textbook Poseidon on this prime.
 */
export function poseidon2(a: bigint, b: bigint): bigint {
  let state = [0n, a % P, b % P].map((x, i) => add(x, C[i]));

  for (let r = 0; r < N_ROUNDS_F / 2 - 1; r++) {
    state = state.map(pow5).map((x, i) => add(x, C[(r + 1) * T + i]));
    state = mix(state, M);
  }
  state = state.map(pow5).map((x, i) => add(x, C[(N_ROUNDS_F / 2) * T + i]));
  state = mix(state, PM);

  for (let r = 0; r < N_ROUNDS_P; r++) {
    state[0] = add(pow5(state[0]), C[(N_ROUNDS_F / 2 + 1) * T + r]);
    const s0 = state.reduce((acc, x, j) => add(acc, mul(S[(T * 2 - 1) * r + j], x)), 0n);
    for (let k = 1; k < T; k++) {
      state[k] = add(state[k], mul(state[0], S[(T * 2 - 1) * r + T + k - 1]));
    }
    state[0] = s0;
  }

  for (let r = 0; r < N_ROUNDS_F / 2 - 1; r++) {
    state = state.map(pow5).map((x, i) => add(x, C[(N_ROUNDS_F / 2 + 1) * T + N_ROUNDS_P + r * T + i]));
    state = mix(state, M);
  }
  state = mix(state.map(pow5), M);
  return state[0];
}
