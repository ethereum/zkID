import hardhatToolboxMochaEthersPlugin from "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import { configVariable, defineConfig } from "hardhat/config";

export default defineConfig({
  plugins: [hardhatToolboxMochaEthersPlugin],
  solidity: {
    version: "0.8.34",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
    // Builds the revocation service for tests and deployment.
    npmFilesToBuild: ["@coordination-network/contracts/revocation/sha256/Sha256Revocation.sol"],
  },
  networks: {
    sepolia: {
      type: "http",
      chainType: "l1",
      url: configVariable("SEPOLIA_RPC_URL"),
      accounts: [configVariable("SEPOLIA_PRIVATE_KEY")],
    },
  },
});
