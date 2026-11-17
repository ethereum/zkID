import { expect } from "chai";
import { network } from "hardhat";
import { createHash, randomBytes } from "node:crypto";
import { RevocationRegistry, sha256Scheme } from "@coordination-network/revocation-registry";

const { ethers, networkHelpers } = await network.create();

const ROOT_DURATION = 3600n;

// A holder's commitment: sha256 of a 32-byte secret.
function newCommitment(): bigint {
  return BigInt("0x" + createHash("sha256").update(randomBytes(32)).digest("hex"));
}

async function deploy() {
  const [issuer, other] = await ethers.getSigners();
  const revocation = await ethers.deployContract("Sha256Revocation");
  const registry = await ethers.deployContract("OpenACRevocationRegistry", [
    await revocation.getAddress(),
    issuer.address,
    ROOT_DURATION,
  ]);

  return { issuer, other, revocation, registry };
}

// Off-chain mirror the issuer uses to compute predecessor indices.
async function deployWithMirror() {
  return { ...(await networkHelpers.loadFixture(deploy)), mirror: new RevocationRegistry([], sha256Scheme) };
}

describe("OpenACRevocationRegistry", () => {
  it("starts empty with root 0 accepted", async () => {
    const { registry } = await networkHelpers.loadFixture(deploy);

    expect(await registry.getRevocationRoot()).to.equal(0n);
    expect(await registry.isValidRoot(0n)).to.equal(true);
  });

  it("revokes a commitment with the same root as the TypeScript registry", async () => {
    const { registry, mirror } = await deployWithMirror();

    for (let i = 0; i < 5; i++) {
      const commitment = newCommitment();
      await registry.revoke(commitment, mirror.lowLeafIndexOf(commitment));
      mirror.revoke(commitment);

      expect(await registry.getRevocationRoot()).to.equal(mirror.root);
      expect(await registry.isRevoked(commitment)).to.equal(true);
    }
  });

  it("revokes a batch", async () => {
    const { registry, mirror } = await deployWithMirror();
    const commitments = Array.from({ length: 4 }, newCommitment);

    await registry.revokeMany(commitments, mirror.lowLeafIndicesOf(commitments));
    mirror.revokeMany(commitments);

    expect(await registry.getRevocationRoot()).to.equal(mirror.root);
  });

  it("unrevokes a commitment", async () => {
    const { registry, mirror } = await deployWithMirror();
    const [a, b] = [newCommitment(), newCommitment()];
    await registry.revokeMany([a, b], mirror.lowLeafIndicesOf([a, b]));
    mirror.revokeMany([a, b]);

    await registry.unrevoke(a, mirror.predecessorIndexOf(a));
    mirror.unrevoke(a);

    expect(await registry.isRevoked(a)).to.equal(false);
    expect(await registry.getRevocationRoot()).to.equal(mirror.root);
  });

  it("lets a holder rebuild the tree from chain and prove non-revocation", async () => {
    const { registry, revocation, mirror } = await deployWithMirror();
    const commitments = Array.from({ length: 6 }, newCommitment);
    await registry.revokeMany(commitments, mirror.lowLeafIndicesOf(commitments));

    const registryId = await registry.REGISTRY_ID();
    const leafCount = await revocation.getRevocationTreeLeafCount(registryId);
    const leaves = [];
    for (let i = 0n; i < leafCount; i++) {
      const [value, nextValue] = await revocation.getLeaf(registryId, i);
      leaves.push({ value, nextValue });
    }
    const synced = RevocationRegistry.fromLeaves(leaves, sha256Scheme);

    expect(synced.root).to.equal(await registry.getRevocationRoot());
    expect(synced.generateProof(newCommitment()).proofType).to.equal(1);
  });

  it("keeps a superseded root valid for the root duration only", async () => {
    const { registry, mirror } = await deployWithMirror();
    const first = newCommitment();
    await registry.revoke(first, mirror.lowLeafIndexOf(first));
    mirror.revoke(first);
    const oldRoot = mirror.root;

    const second = newCommitment();
    await registry.revoke(second, mirror.lowLeafIndexOf(second));

    expect(await registry.isValidRoot(oldRoot)).to.equal(true);
    await networkHelpers.time.increase(ROOT_DURATION);
    expect(await registry.isValidRoot(oldRoot)).to.equal(false);
    expect(await registry.isValidRoot(await registry.getRevocationRoot())).to.equal(true);
  });

  it("only lets the issuer write", async () => {
    const { registry, other } = await networkHelpers.loadFixture(deploy);

    await expect(registry.connect(other).revoke(newCommitment(), 0n))
      .to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount")
      .withArgs(other.address);
  });

  it("transfers the issuer role in two steps", async () => {
    const { registry, other } = await networkHelpers.loadFixture(deploy);

    await registry.transferOwnership(other.address);
    await registry.connect(other).acceptOwnership();

    expect(await registry.owner()).to.equal(other.address);
  });
});
