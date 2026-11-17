import { Circomkit } from "circomkit";

export const circomkit = new Circomkit({
  verbose: false,
  prime: "secq256r1",
  optimization: 2,
  include: ["./node_modules", "./node_modules/circomlib/circuits"],
});
