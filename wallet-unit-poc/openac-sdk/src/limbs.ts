// 256-bit values (registry roots, SHA-256 digests) cross the circuits as two
// 128-bit limbs [hi, lo], since a secq256r1 field element cannot hold 256 bits.

import { VerificationError } from "./errors.js";

const LIMB_BITS = 128n;
const LIMB_MASK = (1n << LIMB_BITS) - 1n;

export function toLimbs(value: bigint): [bigint, bigint] {
  return [value >> LIMB_BITS, value & LIMB_MASK];
}

/** Recombines `hi * 2^128 + lo`, rejecting a limb that does not fit 128 bits. */
export function fromLimbs(hi: bigint, lo: bigint): bigint {
  if (hi < 0n || lo < 0n || hi > LIMB_MASK || lo > LIMB_MASK) {
    throw new VerificationError("INVALID_PROOF_FORMAT", "Root limb is not 128 bits");
  }
  return (hi << LIMB_BITS) | lo;
}
