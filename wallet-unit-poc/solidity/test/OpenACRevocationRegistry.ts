import assert from "node:assert/strict"
import { createHash, randomBytes } from "node:crypto"
import { describe, it } from "node:test"

import { PROOF_TYPE, RevocationRegistry, sha256Scheme } from "@coordination-network/revocation-registry"
import { network } from "hardhat"
import { getAddress, zeroAddress } from "viem"

const { viem, networkHelpers } = await network.create()

const ROOT_DURATION = 3600n

/** A holder's commitment: sha256 of a 32-byte secret. */
function newCommitment(): bigint {
    return BigInt("0x" + createHash("sha256").update(randomBytes(32)).digest("hex"))
}

const commitments = (n: number) => Array.from({ length: n }, newCommitment)

async function deploy() {
    const [owner, issuerA, issuerB, outsider] = await viem.getWalletClients()
    const service = await viem.deployContract("Sha256Revocation")
    const registry = await viem.deployContract("OpenACRevocationRegistry", [
        service.address,
        owner.account.address,
        ROOT_DURATION
    ])
    await registry.write.setRevoker([issuerA.account.address, true])
    await registry.write.setRevoker([issuerB.account.address, true])

    const as = (client: typeof owner) =>
        viem.getContractAt("OpenACRevocationRegistry", registry.address, { client: { wallet: client } })

    return {
        service,
        registry,
        owner,
        issuerA,
        issuerB,
        outsider,
        asA: await as(issuerA),
        asB: await as(issuerB),
        asOutsider: await as(outsider)
    }
}

/** The deployed fixture plus a fresh off-chain mirror, used to compute predecessor indices. */
async function setup() {
    return { ...(await networkHelpers.loadFixture(deploy)), mirror: new RevocationRegistry([], sha256Scheme) }
}

describe("OpenACRevocationRegistry", () => {
    describe("constructor", () => {
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
    })

    describe("revokers", () => {
        it("lets the owner authorize and deauthorize revokers", async () => {
            const { registry, outsider } = await setup()

            await registry.write.setRevoker([outsider.account.address, true])
            assert.equal(await registry.read.isRevoker([outsider.account.address]), true)
            await registry.write.setRevoker([outsider.account.address, false])
            assert.equal(await registry.read.isRevoker([outsider.account.address]), false)

            await viem.assertions.revertWithCustomError(
                registry.write.setRevoker([zeroAddress, true]),
                registry,
                "ZeroRevoker"
            )
        })

        it("gates owner writes on the owner", async () => {
            const { registry, asA, issuerA } = await setup()
            for (const call of [asA.write.setRevoker([issuerA.account.address, true]), asA.write.updateRootDuration([1n])]) {
                await viem.assertions.revertWithCustomErrorWithArgs(call, registry, "OwnableUnauthorizedAccount", [
                    getAddress(issuerA.account.address)
                ])
            }
        })

        it("rejects revocations from accounts that are not revokers, including the owner", async () => {
            const { registry, asOutsider, outsider, owner } = await setup()
            await viem.assertions.revertWithCustomErrorWithArgs(
                asOutsider.write.revoke([newCommitment(), 0n]),
                registry,
                "NotRevoker",
                [getAddress(outsider.account.address)]
            )
            await viem.assertions.revertWithCustomErrorWithArgs(
                registry.write.revoke([newCommitment(), 0n]),
                registry,
                "NotRevoker",
                [getAddress(owner.account.address)]
            )
        })

        it("transfers ownership in two steps", async () => {
            const { registry, asA, issuerA } = await setup()

            await registry.write.transferOwnership([issuerA.account.address])
            await asA.write.acceptOwnership()
            assert.equal(await registry.read.owner(), getAddress(issuerA.account.address))
        })
    })

    describe("one registry for all issuers", () => {
        it("puts every issuer's revocations in one tree whose root matches the TypeScript registry", async () => {
            const { registry, asA, asB, issuerA, issuerB, mirror } = await setup()

            for (const [as, issuer] of [
                [asA, issuerA],
                [asB, issuerB],
                [asA, issuerA]
            ] as const) {
                const c = newCommitment()
                await as.write.revoke([c, mirror.lowLeafIndexOf(c)])
                mirror.revoke(c)

                assert.equal(await registry.read.getRevocationRoot(), mirror.root)
                assert.equal(await registry.read.isRevoked([c]), true)
                assert.equal(await registry.read.revokedBy([c]), getAddress(issuer.account.address))
            }
        })

        it("revokes a batch", async () => {
            const { registry, asA, issuerA, mirror } = await setup()
            const batch = commitments(4)

            await asA.write.revokeMany([batch, mirror.lowLeafIndicesOf(batch)])
            mirror.revokeMany(batch)

            assert.equal(await registry.read.getRevocationRoot(), mirror.root)
            for (const c of batch) assert.equal(await registry.read.revokedBy([c]), getAddress(issuerA.account.address))

            await viem.assertions.revertWithCustomError(
                asA.write.revokeMany([commitments(2), [0n]]),
                registry,
                "LengthMismatch"
            )
        })

        it("lets only the issuer that revoked a commitment unrevoke it", async () => {
            const { registry, asA, asB, issuerB, mirror } = await setup()
            const [a, b] = commitments(2)
            await asA.write.revokeMany([[a, b], mirror.lowLeafIndicesOf([a, b])])
            mirror.revokeMany([a, b])

            await viem.assertions.revertWithCustomErrorWithArgs(
                asB.write.unrevoke([a, mirror.predecessorIndexOf(a)]),
                registry,
                "NotCommitmentRevoker",
                [a, getAddress(issuerB.account.address)]
            )

            await asA.write.unrevoke([a, mirror.predecessorIndexOf(a)])
            mirror.unrevoke(a)
            assert.equal(await registry.read.isRevoked([a]), false)
            assert.equal(await registry.read.revokedBy([a]), zeroAddress)
            assert.equal(await registry.read.getRevocationRoot(), mirror.root)
        })

        it("lets only the issuer that revoked a commitment update it, and moves the record", async () => {
            const { registry, asA, asB, issuerA, issuerB, mirror } = await setup()
            const [a, b] = commitments(2)
            await asA.write.revoke([a, mirror.lowLeafIndexOf(a)])
            mirror.revoke(a)

            // The new commitment's predecessor is taken after the old one is unlinked.
            const unlinked = new RevocationRegistry([a], sha256Scheme)
            unlinked.unrevoke(a)
            const args = () =>
                [a, b, mirror.predecessorIndexOf(a), unlinked.lowLeafIndexOf(b)] as const
            await viem.assertions.revertWithCustomErrorWithArgs(
                asB.write.updateRevocationCommitment([...args()]),
                registry,
                "NotCommitmentRevoker",
                [a, getAddress(issuerB.account.address)]
            )

            await asA.write.updateRevocationCommitment([...args()])
            mirror.updateCommitment(a, b)
            assert.equal(await registry.read.revokedBy([a]), zeroAddress)
            assert.equal(await registry.read.revokedBy([b]), getAddress(issuerA.account.address))
            assert.equal(await registry.read.getRevocationRoot(), mirror.root)
        })

        it("freezes a deauthorized revoker's revocations", async () => {
            const { registry, asA, issuerA, mirror } = await setup()
            const c = newCommitment()
            await asA.write.revoke([c, mirror.lowLeafIndexOf(c)])
            mirror.revoke(c)

            await registry.write.setRevoker([issuerA.account.address, false])
            await viem.assertions.revertWithCustomErrorWithArgs(
                asA.write.unrevoke([c, mirror.predecessorIndexOf(c)]),
                registry,
                "NotRevoker",
                [getAddress(issuerA.account.address)]
            )
            assert.equal(await registry.read.isRevoked([c]), true)
        })
    })

    describe("holders and verifiers", () => {
        it("lets a holder rebuild the tree from chain and prove non-revocation", async () => {
            const { registry, service, asA, asB, mirror } = await setup()
            const fromA = commitments(3)
            const fromB = commitments(3)
            await asA.write.revokeMany([fromA, mirror.lowLeafIndicesOf(fromA)])
            mirror.revokeMany(fromA)
            await asB.write.revokeMany([fromB, mirror.lowLeafIndicesOf(fromB)])
            mirror.revokeMany(fromB)

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
            assert.equal(synced.generateProof(fromB[0]!).proofType, PROOF_TYPE.MEMBERSHIP)
        })

        it("keeps a superseded root valid for the root duration only", async () => {
            const { registry, asA, mirror } = await setup()
            const first = newCommitment()
            await asA.write.revoke([first, mirror.lowLeafIndexOf(first)])
            mirror.revoke(first)
            const oldRoot = mirror.root

            const second = newCommitment()
            await asA.write.revoke([second, mirror.lowLeafIndexOf(second)])

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
    })
})
