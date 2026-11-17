import assert from "node:assert/strict"
import { describe, it } from "node:test"

import { IssuerRegistry, sha256Hash2, sha256Scheme } from "@coordination-network/issuer-registry"
import { p256 } from "@noble/curves/nist.js"
import { network } from "hardhat"
import { getAddress, zeroAddress } from "viem"

const { viem, networkHelpers } = await network.create()

const MAX_DEPTH = 8n
const ROOT_DURATION = 3600n

/** `sha256(be32(x) || be32(y))` of a fresh P-256 key, as the circuit derives the leaf. */
function randomIssuerCommitment(): bigint {
    const publicKey = p256.getPublicKey(p256.utils.randomSecretKey(), false)
    const { x, y } = p256.Point.fromBytes(publicKey).toAffine()
    return sha256Hash2(x, y)
}

const commitments = (n: number) => Array.from({ length: n }, randomIssuerCommitment)

async function deploy(maxDepth = MAX_DEPTH, rootDuration = ROOT_DURATION) {
    const [owner, other] = await viem.getWalletClients()
    const service = await viem.deployContract("Sha256IssuerRegistry")
    const registry = await viem.deployContract("OpenACIssuerRegistry", [
        service.address,
        maxDepth,
        rootDuration,
        owner.account.address
    ])
    const asOther = await viem.getContractAt("OpenACIssuerRegistry", registry.address, {
        client: { wallet: other }
    })
    return { service, registry, asOther, owner, other }
}

describe("OpenACIssuerRegistry", () => {
    describe("constructor", () => {
        it("creates a registry on the service administered by itself", async () => {
            const { service, registry, owner } = await deploy()

            assert.equal(await registry.read.ISSUER_REGISTRY(), getAddress(service.address))
            assert.equal(await registry.read.REGISTRY_ID(), 0n)
            assert.equal(await registry.read.MAX_DEPTH(), MAX_DEPTH)
            assert.equal(await registry.read.owner(), getAddress(owner.account.address))
            assert.equal(await service.read.registryCounter(), 1n)
            assert.equal(await service.read.getRegistryAdmin([0n]), getAddress(registry.address))
            assert.equal(await service.read.getRegistryRootDuration([0n]), ROOT_DURATION)
            assert.equal(await registry.read.getIssuerRoot(), 0n)
        })

        it("uses its own registry id when the service is shared", async () => {
            const { service } = await deploy()
            const [owner] = await viem.getWalletClients()
            const second = await viem.deployContract("OpenACIssuerRegistry", [
                service.address,
                MAX_DEPTH,
                ROOT_DURATION,
                owner.account.address
            ])
            assert.equal(await second.read.REGISTRY_ID(), 1n)
        })

        it("reverts on a zero service or zero max depth", async () => {
            const { registry, service, owner } = await deploy()
            await viem.assertions.revertWithCustomError(
                viem.deployContract("OpenACIssuerRegistry", [zeroAddress, MAX_DEPTH, ROOT_DURATION, owner.account.address]),
                registry,
                "ZeroIssuerRegistry"
            )
            await viem.assertions.revertWithCustomError(
                viem.deployContract("OpenACIssuerRegistry", [service.address, 0n, ROOT_DURATION, owner.account.address]),
                registry,
                "ZeroMaxDepth"
            )
        })
    })

    describe("access control", () => {
        it("gates every write on the owner", async () => {
            const { registry, asOther, other } = await deploy()
            const [c] = commitments(1)
            await registry.write.addIssuer([c])

            const calls = [
                asOther.write.addIssuer([randomIssuerCommitment()]),
                asOther.write.addIssuers([commitments(2)]),
                asOther.write.removeIssuer([c, []]),
                asOther.write.updateIssuerCommitment([c, randomIssuerCommitment(), []]),
                asOther.write.updateRootDuration([1n]),
                asOther.write.expireRoots()
            ]
            for (const call of calls) {
                await viem.assertions.revertWithCustomErrorWithArgs(call, registry, "OwnableUnauthorizedAccount", [
                    getAddress(other.account.address)
                ])
            }
        })

        it("transfers ownership in two steps", async () => {
            const { registry, asOther, owner, other } = await deploy()

            await registry.write.transferOwnership([other.account.address])
            assert.equal(await registry.read.owner(), getAddress(owner.account.address))
            assert.equal(await registry.read.pendingOwner(), getAddress(other.account.address))

            await asOther.write.acceptOwnership()
            assert.equal(await registry.read.owner(), getAddress(other.account.address))

            await asOther.write.addIssuer([randomIssuerCommitment()])
            await viem.assertions.revertWithCustomError(
                registry.write.addIssuer([randomIssuerCommitment()]),
                registry,
                "OwnableUnauthorizedAccount"
            )
        })
    })

    describe("writes", () => {
        it("adds, removes and updates issuers in step with the TypeScript registry", async () => {
            const { registry } = await deploy()
            const mirror = new IssuerRegistry([], sha256Scheme)
            const [a, b, c, d, e] = commitments(5)

            await registry.write.addIssuer([a])
            mirror.addIssuer(a)
            assert.equal(await registry.read.getIssuerRoot(), mirror.root)

            await registry.write.addIssuers([[b, c, d]])
            mirror.addIssuers([b, c, d])
            assert.equal(await registry.read.getIssuerRoot(), mirror.root)
            for (const x of [a, b, c, d]) assert.equal(await registry.read.isIssuer([x]), true)

            await registry.write.removeIssuer([b, mirror.siblingNodesOf(b)])
            mirror.removeIssuer(b)
            assert.equal(await registry.read.getIssuerRoot(), mirror.root)
            assert.equal(await registry.read.isIssuer([b]), false)

            await registry.write.updateIssuerCommitment([c, e, mirror.siblingNodesOf(c)])
            mirror.updateIssuerCommitment(c, e)
            assert.equal(await registry.read.getIssuerRoot(), mirror.root)
            assert.equal(await registry.read.isIssuer([c]), false)
            assert.equal(await registry.read.isIssuer([e]), true)
        })

        it("updates the root duration", async () => {
            const { service, registry } = await deploy()
            await registry.write.updateRootDuration([60n])
            assert.equal(await service.read.getRegistryRootDuration([await registry.read.REGISTRY_ID()]), 60n)
        })
    })

    describe("isValidRoot", () => {
        it("rejects the zero root and unknown roots", async () => {
            const { registry } = await deploy()
            assert.equal(await registry.read.isValidRoot([0n]), false)
            await registry.write.addIssuer([randomIssuerCommitment()])
            assert.equal(await registry.read.isValidRoot([0n]), false)
            assert.equal(await registry.read.isValidRoot([123n]), false)
        })

        it("accepts the current root and a superseded root within the window", async () => {
            const { registry } = await deploy()
            await registry.write.addIssuer([randomIssuerCommitment()])
            const oldRoot = await registry.read.getIssuerRoot()

            await registry.write.addIssuer([randomIssuerCommitment()])
            const newRoot = await registry.read.getIssuerRoot()
            assert.notEqual(newRoot, oldRoot)
            assert.equal(await registry.read.isValidRoot([newRoot]), true)
            assert.equal(await registry.read.isValidRoot([oldRoot]), true)

            await networkHelpers.time.increase(ROOT_DURATION / 2n)
            assert.equal(await registry.read.isValidRoot([oldRoot]), true)

            await networkHelpers.time.increase(ROOT_DURATION / 2n)
            assert.equal(await registry.read.isValidRoot([oldRoot]), false)
            assert.equal(await registry.read.isValidRoot([newRoot]), true)
        })

        it("rejects every superseded root after expireRoots", async () => {
            const { registry } = await deploy()
            const mirror = new IssuerRegistry([], sha256Scheme)
            const [a, b] = commitments(2)

            await registry.write.addIssuers([[a, b]])
            mirror.addIssuers([a, b])
            const rootWithA = mirror.root

            await registry.write.removeIssuer([a, mirror.siblingNodesOf(a)])
            mirror.removeIssuer(a)
            assert.equal(await registry.read.isValidRoot([rootWithA]), true)

            await registry.write.expireRoots()
            assert.equal(await registry.read.isValidRoot([rootWithA]), false)
            assert.equal(await registry.read.isValidRoot([mirror.root]), true)
        })
    })

    describe("MAX_DEPTH", () => {
        it("reverts addIssuer when the tree would exceed the max depth", async () => {
            const { registry } = await deploy(2n)
            for (const c of commitments(4)) await registry.write.addIssuer([c])

            await viem.assertions.revertWithCustomErrorWithArgs(
                registry.write.addIssuer([randomIssuerCommitment()]),
                registry,
                "MaxDepthExceeded",
                [3n, 2n]
            )
        })

        it("reverts addIssuers when the batch would exceed the max depth", async () => {
            const { registry } = await deploy(2n)
            await viem.assertions.revertWithCustomErrorWithArgs(
                registry.write.addIssuers([commitments(5)]),
                registry,
                "MaxDepthExceeded",
                [3n, 2n]
            )
            await registry.write.addIssuers([commitments(4)])
        })

        it("holds 256 issuers at depth 8 and rejects the 257th", async () => {
            const { service, registry } = await deploy()
            const all = commitments(256)
            await registry.write.addIssuers([all.slice(0, 128)])
            await registry.write.addIssuers([all.slice(128)])
            assert.equal(await service.read.getIssuerTreeDepth([await registry.read.REGISTRY_ID()]), 8n)
            assert.equal(await registry.read.getIssuerRoot(), new IssuerRegistry(all, sha256Scheme).root)

            await viem.assertions.revertWithCustomErrorWithArgs(
                registry.write.addIssuer([randomIssuerCommitment()]),
                registry,
                "MaxDepthExceeded",
                [9n, 8n]
            )
        })

        it("still allows removals and updates on a full tree", async () => {
            const { registry } = await deploy(1n)
            const [a, b, c] = commitments(3)
            const mirror = new IssuerRegistry([a, b], sha256Scheme)
            await registry.write.addIssuers([[a, b]])

            await registry.write.removeIssuer([a, mirror.siblingNodesOf(a)])
            mirror.removeIssuer(a)
            await registry.write.updateIssuerCommitment([b, c, mirror.siblingNodesOf(b)])
            mirror.updateIssuerCommitment(b, c)
            assert.equal(await registry.read.getIssuerRoot(), mirror.root)
        })
    })

    describe("cross-language root", () => {
        it("matches new IssuerRegistry(sha256Hash2(x, y) of P-256 keys, sha256Scheme).root", async () => {
            for (const n of [1, 2, 3, 7, 16]) {
                const { registry } = await deploy()
                const leaves = commitments(n)
                await registry.write.addIssuers([leaves])

                const root = await registry.read.getIssuerRoot()
                assert.equal(root, new IssuerRegistry(leaves, sha256Scheme).root)
                assert.equal(await registry.read.isValidRoot([root]), true)

            }
        })
    })
})
