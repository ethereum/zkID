import { buildModule } from "@nomicfoundation/hardhat-ignition/modules"

export default buildModule("OpenACIssuerRegistryModule", (m) => {
    const maxDepth = m.getParameter("maxDepth", 8n)
    const rootDuration = m.getParameter("rootDuration", 3600n)
    const owner = m.getParameter("owner", m.getAccount(0))

    const sha256IssuerRegistry = m.contract("Sha256IssuerRegistry")
    const openACIssuerRegistry = m.contract("OpenACIssuerRegistry", [
        sha256IssuerRegistry,
        maxDepth,
        rootDuration,
        owner
    ])

    return { sha256IssuerRegistry, openACIssuerRegistry }
})
