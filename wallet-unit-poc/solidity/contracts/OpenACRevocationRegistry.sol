// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import { Ownable, Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { IRevocation } from "@coordination-network/contracts/revocation/interfaces/IRevocation.sol";
import { IRevocationRegistries } from "@coordination-network/contracts/revocation/interfaces/IRevocationRegistries.sol";

/// @title OpenACRevocationRegistry
/// @notice An issuer's OpenAC revocation registry: a SHA-256 LeanIMT+ of revoked commitments
/// `sha256(be32(x) || be32(y) || be32(r) || be32(3))` (issuer key (x, y), signed revocation value r),
/// held on a `Sha256Revocation` service. Writes take commitments (`computeRevocationCommitment` in
/// openac-sdk), not the credential's `revocation_value` r. Only the issuer (owner) writes; verifiers
/// accept a presentation's revocation root with {isValidRoot}.
/// @dev One registry per issuer does not leak anything: the issuer key is already public in the
/// OpenAC presentation. Holders read the tree from {REVOCATION} under {REGISTRY_ID} (`getLeaf`).
contract OpenACRevocationRegistry is Ownable2Step {
    /// @notice The revocation service holding this registry's tree and root history.
    IRevocation public immutable REVOCATION;

    /// @notice This registry's id on {REVOCATION}, administered by this contract.
    uint256 public immutable REGISTRY_ID;

    error ZeroRevocationService();

    /// @param revocation A `Sha256Revocation` deployment.
    /// @param issuer The owner, allowed to revoke.
    /// @param rootDuration How long a superseded root stays valid, in seconds.
    constructor(IRevocation revocation, address issuer, uint256 rootDuration) Ownable(issuer) {
        if (address(revocation) == address(0)) revert ZeroRevocationService();

        REVOCATION = revocation;
        REGISTRY_ID = revocation.createRegistry(address(this), rootDuration);
    }

    /// @param lowLeafIndex The commitment's predecessor slot, from `registry.lowLeafIndexOf`.
    function revoke(uint256 revocationCommitment, uint256 lowLeafIndex) external onlyOwner {
        REVOCATION.revoke(REGISTRY_ID, revocationCommitment, lowLeafIndex);
    }

    /// @param lowLeafIndices From `registry.lowLeafIndicesOf`.
    function revokeMany(uint256[] calldata revocationCommitments, uint256[] calldata lowLeafIndices)
        external
        onlyOwner
    {
        REVOCATION.revokeMany(REGISTRY_ID, revocationCommitments, lowLeafIndices);
    }

    /// @param predecessorIndex From `registry.predecessorIndexOf`.
    function unrevoke(uint256 revocationCommitment, uint256 predecessorIndex) external onlyOwner {
        REVOCATION.unrevoke(REGISTRY_ID, revocationCommitment, predecessorIndex);
    }

    function updateRevocationCommitment(
        uint256 oldRevocationCommitment,
        uint256 newRevocationCommitment,
        uint256 oldPredecessorIndex,
        uint256 newPredecessorIndex
    ) external onlyOwner {
        REVOCATION.updateRevocationCommitment(
            REGISTRY_ID, oldRevocationCommitment, newRevocationCommitment, oldPredecessorIndex, newPredecessorIndex
        );
    }

    function updateRootDuration(uint256 rootDuration) external onlyOwner {
        REVOCATION.updateRegistryRootDuration(REGISTRY_ID, rootDuration);
    }

    /// @notice Whether a presentation's revocation root is accepted: the current root, or one
    /// superseded less than the root duration ago.
    function isValidRoot(uint256 revocationRoot) external view returns (bool) {
        return REVOCATION.isValidRoot(REGISTRY_ID, revocationRoot);
    }

    /// @notice The current root, zero while empty.
    function getRevocationRoot() external view returns (uint256) {
        return IRevocationRegistries(address(REVOCATION)).getRevocationRoot(REGISTRY_ID);
    }

    function isRevoked(uint256 revocationCommitment) external view returns (bool) {
        return IRevocationRegistries(address(REVOCATION)).isRevoked(REGISTRY_ID, revocationCommitment);
    }
}
