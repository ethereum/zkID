import assert from "node:assert/strict"
import { createHash, randomBytes } from "node:crypto"
import { describe, it } from "node:test"

import { PROOF_TYPE, RevocationRegistry, sha256Scheme } from "@coordination-network/revocation-registry"
import { network } from "hardhat"
import { getAddress, zeroAddress } from "viem"

const { viem, networkHelpers } = await network.create()

const ROOT_DURATION = 3600n

/** A random revocation commitment, standing in for computeRevocationCommitment. */
function newCommitment(): bigint {
    return BigInt("0x" + createHash("sha256").update(randomBytes(32)).digest("hex"))
}

const commitments = (n: number) => Array.from({ length: n }, newCommitment)

async function deploy() {
    const [owner, other] = await viem.getWalletClients()
    const service = await viem.deployContract("Sha256Revocation")
    const registry = await viem.deployContract("OpenACRevocationRegistry", [
        service.address,
        owner.account.address,
        ROOT_DURATION
    ])
    const asOther = await viem.getContractAt("OpenACRevocationRegistry", registry.address, {
        client: { wallet: other }
    })

    return { service, registry, owner, other, asOther }
}

/** The deployed fixture plus a fresh off-chain mirror, used to compute predecessor indices. */
async function setup() {
    return { ...(await networkHelpers.loadFixture(deploy)), mirror: new RevocationRegistry([], sha256Scheme) }
}

describe("OpenACRevocationRegistry", () => {
    it("creates one registry on the service administered by itself, empty with root 0 accepted", async () => {
        const { service, registry, owner } = await setup()

        assert.equal(await registry.read.REVOCATION(), getAddress(service.address))
        assert.equal(await registry.read.owner(), getAddress(owner.account.address))
        assert.equal(await service.read.getRegistryAdmin([await registry.read.REGISTRY_ID()]), getAddress(registry.address))
        assert.equal(await registry.read.getRevocationRoot(), 0n)
        assert.equal(await registry.read.isValidRoot([0n]), true)
    })

    it("reverts on a zero service", async () => {
        const { registry, owner } = await setup()
        await viem.assertions.revertWithCustomError(
            viem.deployContract("OpenACRevocationRegistry", [zeroAddress, owner.account.address, ROOT_DURATION]),
            registry,
            "ZeroRevocationService"
        )
    })

    it("revokes commitments with the same root as the TypeScript registry", async () => {
        const { registry, mirror } = await setup()

        for (let i = 0; i < 5; i++) {
            const c = newCommitment()
            await registry.write.revoke([c, BigInt(mirror.lowLeafIndexOf(c))])
            mirror.revoke(c)

            assert.equal(await registry.read.getRevocationRoot(), mirror.root)
            assert.equal(await registry.read.isRevoked([c]), true)
        }
    })

    it("revokes a batch", async () => {
        const { registry, mirror } = await setup()
        const batch = commitments(4)

        await registry.write.revokeMany([batch, mirror.lowLeafIndicesOf(batch).map(BigInt)])
        mirror.revokeMany(batch)

        assert.equal(await registry.read.getRevocationRoot(), mirror.root)
    })

    it("unrevokes a commitment", async () => {
        const { registry, mirror } = await setup()
        const [a, b] = commitments(2)
        await registry.write.revokeMany([[a, b], mirror.lowLeafIndicesOf([a, b]).map(BigInt)])
        mirror.revokeMany([a, b])

        await registry.write.unrevoke([a, BigInt(mirror.predecessorIndexOf(a))])
        mirror.unrevoke(a)

        assert.equal(await registry.read.isRevoked([a]), false)
        assert.equal(await registry.read.getRevocationRoot(), mirror.root)
    })

    it("updates a revoked commitment", async () => {
        const { registry, mirror } = await setup()
        const [a, b] = commitments(2)
        await registry.write.revoke([a, BigInt(mirror.lowLeafIndexOf(a))])
        mirror.revoke(a)

        // The new commitment's predecessor is taken after the old one is unlinked.
        const unlinked = new RevocationRegistry([a], sha256Scheme)
        unlinked.unrevoke(a)
        await registry.write.updateRevocationCommitment([
            a,
            b,
            BigInt(mirror.predecessorIndexOf(a)),
            BigInt(unlinked.lowLeafIndexOf(b))
        ])
        mirror.updateCommitment(a, b)

        assert.equal(await registry.read.isRevoked([a]), false)
        assert.equal(await registry.read.isRevoked([b]), true)
        assert.equal(await registry.read.getRevocationRoot(), mirror.root)
    })

    it("lets a holder rebuild the tree from chain and prove non-revocation", async () => {
        const { registry, service, mirror } = await setup()
        const revoked = commitments(6)
        await registry.write.revokeMany([revoked, mirror.lowLeafIndicesOf(revoked).map(BigInt)])

        const registryId = await registry.read.REGISTRY_ID()
        const leafCount = await service.read.getRevocationTreeLeafCount([registryId])
        const leaves = []
        for (let i = 0n; i < leafCount; i++) {
            const [value, nextValue] = await service.read.getLeaf([registryId, i])
            leaves.push({ value, nextValue })
        }
        const synced = RevocationRegistry.fromLeaves(leaves, sha256Scheme)

        assert.equal(synced.root, await registry.read.getRevocationRoot())
        assert.equal(synced.generateProof(newCommitment()).proofType, PROOF_TYPE.NON_MEMBERSHIP)
        assert.equal(synced.generateProof(revoked[0]!).proofType, PROOF_TYPE.MEMBERSHIP)
    })

    it("keeps a superseded root valid for the root duration only", async () => {
        const { registry, mirror } = await setup()
        const first = newCommitment()
        await registry.write.revoke([first, BigInt(mirror.lowLeafIndexOf(first))])
        mirror.revoke(first)
        const oldRoot = mirror.root

        const second = newCommitment()
        await registry.write.revoke([second, BigInt(mirror.lowLeafIndexOf(second))])

        assert.equal(await registry.read.isValidRoot([oldRoot]), true)
        await networkHelpers.time.increase(ROOT_DURATION)
        assert.equal(await registry.read.isValidRoot([oldRoot]), false)
        assert.equal(await registry.read.isValidRoot([await registry.read.getRevocationRoot()]), true)
    })

    it("updates the root duration", async () => {
        const { service, registry } = await setup()
        await registry.write.updateRootDuration([60n])
        assert.equal(await service.read.getRegistryRootDuration([await registry.read.REGISTRY_ID()]), 60n)
    })

    it("only lets the owner write", async () => {
        const { registry, asOther, other } = await setup()
        for (const call of [
            asOther.write.revoke([newCommitment(), 0n]),
            asOther.write.revokeMany([[newCommitment()], [0n]]),
            asOther.write.unrevoke([newCommitment(), 0n]),
            asOther.write.updateRevocationCommitment([newCommitment(), newCommitment(), 0n, 0n]),
            asOther.write.updateRootDuration([1n])
        ]) {
            await viem.assertions.revertWithCustomErrorWithArgs(call, registry, "OwnableUnauthorizedAccount", [
                getAddress(other.account.address)
            ])
        }
    })

    it("transfers ownership in two steps", async () => {
        const { registry, asOther, other } = await setup()

        await registry.write.transferOwnership([other.account.address])
        await asOther.write.acceptOwnership()
        assert.equal(await registry.read.owner(), getAddress(other.account.address))
    })
})
