import hardhatToolboxViemPlugin from "@nomicfoundation/hardhat-toolbox-viem"
import { configVariable, defineConfig } from "hardhat/config"

export default defineConfig({
    plugins: [hardhatToolboxViemPlugin],
    solidity: {
        version: "0.8.34",
        // Hardhat 3 emits artifacts only for project files, so the shared services are listed to be deployable here.
        npmFilesToBuild: [
            "@coordination-network/contracts/issuer-registry/sha256/Sha256IssuerRegistry.sol",
            "@coordination-network/contracts/revocation/sha256/Sha256Revocation.sol"
        ],
        settings: {
            optimizer: { enabled: true, runs: 200 },
            evmVersion: "prague"
        }
    },
    networks: {
        sepolia: {
            type: "http",
            chainType: "l1",
            url: configVariable("SEPOLIA_RPC_URL"),
            accounts: [configVariable("SEPOLIA_PRIVATE_KEY")]
        }
    }
})
