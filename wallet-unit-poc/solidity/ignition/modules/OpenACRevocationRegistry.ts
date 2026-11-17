import { buildModule } from "@nomicfoundation/hardhat-ignition/modules"

export default buildModule("OpenACRevocationRegistryModule", (m) => {
    const rootDuration = m.getParameter("rootDuration", 3600n)
    const owner = m.getParameter("owner", m.getAccount(0))

    const sha256Revocation = m.contract("Sha256Revocation")
    const openACRevocationRegistry = m.contract("OpenACRevocationRegistry", [
        sha256Revocation,
        owner,
        rootDuration
    ])

    return { sha256Revocation, openACRevocationRegistry }
})
