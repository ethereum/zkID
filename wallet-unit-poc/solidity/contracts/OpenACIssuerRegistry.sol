// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { IIssuerRegistry } from "@coordination-network/contracts/issuer-registry/interfaces/IIssuerRegistry.sol";
import { IIssuerRegistries } from "@coordination-network/contracts/issuer-registry/interfaces/IIssuerRegistries.sol";

/// @title OpenACIssuerRegistry
/// @notice OpenAC's approved-issuer set: one SHA-256 LeanIMT of issuer commitments
/// `sha256(be32(pubKeyX) || be32(pubKeyY))`, held on a shared {IIssuerRegistry} service.
/// @dev The Show circuit proves the issuer is a leaf and outputs the root, so a verifier only calls
/// {isValidRoot}: the issuer never appears. This contract is the registry admin and adds owner gating
/// plus a depth cap matching the circuit. Tree reads for holders live on {ISSUER_REGISTRY} under {REGISTRY_ID}.
contract OpenACIssuerRegistry is Ownable2Step {
    /// @notice The service holding the tree and its root history.
    IIssuerRegistry public immutable ISSUER_REGISTRY;

    /// @notice This registry's id on {ISSUER_REGISTRY}.
    uint256 public immutable REGISTRY_ID;

    /// @notice The deepest tree the circuit can prove membership in (OpenAC: 8, i.e. 256 issuers).
    uint256 public immutable MAX_DEPTH;

    error ZeroIssuerRegistry();
    error ZeroMaxDepth();
    error MaxDepthExceeded(uint256 depth, uint256 maxDepth);

    /// @param issuerRegistry The `Sha256IssuerRegistry` service deployment.
    /// @param maxDepth The circuit's maximum tree depth.
    /// @param rootDuration How long a superseded root stays valid, in seconds.
    /// @param initialOwner The account allowed to write.
    constructor(IIssuerRegistry issuerRegistry, uint256 maxDepth, uint256 rootDuration, address initialOwner)
        Ownable(initialOwner)
    {
        if (address(issuerRegistry) == address(0)) revert ZeroIssuerRegistry();
        if (maxDepth == 0) revert ZeroMaxDepth();

        ISSUER_REGISTRY = issuerRegistry;
        MAX_DEPTH = maxDepth;
        REGISTRY_ID = issuerRegistry.createRegistry(address(this), rootDuration);
    }

    /// @dev Only inserts grow the tree, so only they are checked.
    modifier withinMaxDepth() {
        _;
        uint256 depth = _registries().getIssuerTreeDepth(REGISTRY_ID);
        if (depth > MAX_DEPTH) revert MaxDepthExceeded(depth, MAX_DEPTH);
    }

    function addIssuer(uint256 issuerCommitment) external onlyOwner withinMaxDepth {
        ISSUER_REGISTRY.addIssuer(REGISTRY_ID, issuerCommitment);
    }

    function addIssuers(uint256[] calldata issuerCommitments) external onlyOwner withinMaxDepth {
        ISSUER_REGISTRY.addIssuers(REGISTRY_ID, issuerCommitments);
    }

    /// @param siblingNodes The commitment's Merkle siblings against the current root.
    function removeIssuer(uint256 issuerCommitment, uint256[] calldata siblingNodes) external onlyOwner {
        ISSUER_REGISTRY.removeIssuer(REGISTRY_ID, issuerCommitment, siblingNodes);
    }

    /// @param siblingNodes The old commitment's Merkle siblings against the current root.
    function updateIssuerCommitment(
        uint256 oldIssuerCommitment,
        uint256 newIssuerCommitment,
        uint256[] calldata siblingNodes
    ) external onlyOwner {
        ISSUER_REGISTRY.updateIssuerCommitment(REGISTRY_ID, oldIssuerCommitment, newIssuerCommitment, siblingNodes);
    }

    function updateRootDuration(uint256 newRootDuration) external onlyOwner {
        ISSUER_REGISTRY.updateRegistryRootDuration(REGISTRY_ID, newRootDuration);
    }

    /// @notice Rejects every superseded root. Call after removing a compromised issuer.
    function expireRoots() external onlyOwner {
        ISSUER_REGISTRY.expireRegistryRoots(REGISTRY_ID);
    }

    /// @notice Whether a proof's issuer root is accepted: the current non-empty root, or one superseded
    /// within the root duration and after the last {expireRoots}.
    function isValidRoot(uint256 issuerRoot) external view returns (bool) {
        return ISSUER_REGISTRY.isValidRoot(REGISTRY_ID, issuerRoot);
    }

    /// @notice The current root, zero while the tree is empty.
    function getIssuerRoot() external view returns (uint256) {
        return _registries().getIssuerRoot(REGISTRY_ID);
    }

    function isIssuer(uint256 issuerCommitment) external view returns (bool) {
        return _registries().isIssuer(REGISTRY_ID, issuerCommitment);
    }

    /// @dev Tree reads live on {IIssuerRegistries}, which the same deployment implements.
    function _registries() private view returns (IIssuerRegistries) {
        return IIssuerRegistries(address(ISSUER_REGISTRY));
    }
}
