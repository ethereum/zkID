import { Circomkit } from "circomkit";

// Circomkit config shared by the input generators and tests.
export const circomkit = new Circomkit({
  verbose: false,
  prime: "secq256r1",
  optimization: 2,
});
