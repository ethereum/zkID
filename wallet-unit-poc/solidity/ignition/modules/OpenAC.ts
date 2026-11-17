import { buildModule } from "@nomicfoundation/hardhat-ignition/modules"

import OpenACIssuerRegistryModule from "./OpenACIssuerRegistry.js"
import OpenACRevocationRegistryModule from "./OpenACRevocationRegistry.js"

/** Both OpenAC registries: approved issuers and the revocation registry shared by all of them. */
export default buildModule("OpenACModule", (m) => {
    const issuers = m.useModule(OpenACIssuerRegistryModule)
    const revocation = m.useModule(OpenACRevocationRegistryModule)

    return { ...issuers, ...revocation }
})
