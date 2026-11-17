import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("OpenACRevocation", (m) => {
  const issuer = m.getParameter("issuer", m.getAccount(0));
  const rootDuration = m.getParameter("rootDuration", 3600n);

  const revocation = m.contract("Sha256Revocation");
  const registry = m.contract("OpenACRevocationRegistry", [revocation, issuer, rootDuration]);

  return { revocation, registry };
});
