// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import { Ownable, Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { IRevocation } from "@coordination-network/contracts/revocation/interfaces/IRevocation.sol";
import { IRevocationRegistries } from "@coordination-network/contracts/revocation/interfaces/IRevocationRegistries.sol";

/// @title OpenACRevocationRegistry
/// @notice OpenAC's revocation registry, shared by every issuer: one SHA-256 LeanIMT+ of revoked
/// `sha256(r)` commitments, held on a `Sha256Revocation` service. Verifiers accept a presentation's
/// revocation root with {isValidRoot}.
/// @dev The Show circuit outputs the revocation root, and issuer hiding keeps the issuer private. With
/// one registry per issuer the root would name the issuer, so all issuers write to this one tree.
/// The owner authorizes revoker accounts (one per issuer). Each revoked commitment records the revoker
/// that inserted it, and only that revoker can unrevoke or update it, so one issuer cannot undo another
/// issuer's revocations. A commitment is only known to its holder and issuer until it is revoked, so
/// another issuer cannot revoke a credential it did not issue. The revoker of a commitment is public,
/// but presentations expose only the root, never the commitment, so this does not link presentations
/// to an issuer. Holders read the tree from {REVOCATION} under {REGISTRY_ID} (`getLeaf`).
contract OpenACRevocationRegistry is Ownable2Step {
    /// @notice The revocation service holding this registry's tree and root history.
    IRevocation public immutable REVOCATION;

    /// @notice This registry's id on {REVOCATION}, administered by this contract.
    uint256 public immutable REGISTRY_ID;

    /// @notice Whether an account may revoke, i.e. acts for an issuer.
    mapping(address account => bool) public isRevoker;

    /// @notice The revoker that inserted a revoked commitment; zero when not revoked.
    mapping(uint256 revocationCommitment => address) public revokedBy;

    event RevokerUpdated(address indexed account, bool authorized);

    error ZeroRevocationService();
    error ZeroRevoker();
    error NotRevoker(address account);
    error NotCommitmentRevoker(uint256 revocationCommitment, address account);
    error LengthMismatch();

    /// @param revocation A `Sha256Revocation` deployment.
    /// @param initialOwner The account that authorizes revokers and sets the root duration.
    /// @param rootDuration How long a superseded root stays valid, in seconds.
    constructor(IRevocation revocation, address initialOwner, uint256 rootDuration) Ownable(initialOwner) {
        if (address(revocation) == address(0)) revert ZeroRevocationService();

        REVOCATION = revocation;
        REGISTRY_ID = revocation.createRegistry(address(this), rootDuration);
    }

    modifier onlyRevoker() {
        if (!isRevoker[msg.sender]) revert NotRevoker(msg.sender);
        _;
    }

    /// @dev The caller must still be a revoker and must be the one that revoked `revocationCommitment`.
    modifier onlyCommitmentRevoker(uint256 revocationCommitment) {
        if (!isRevoker[msg.sender]) revert NotRevoker(msg.sender);
        if (revokedBy[revocationCommitment] != msg.sender) {
            revert NotCommitmentRevoker(revocationCommitment, msg.sender);
        }
        _;
    }

    /// @notice Authorizes or deauthorizes a revoker. A deauthorized revoker keeps its existing
    /// revocations but can no longer revoke, unrevoke or update.
    function setRevoker(address account, bool authorized) external onlyOwner {
        if (account == address(0)) revert ZeroRevoker();

        isRevoker[account] = authorized;
        emit RevokerUpdated(account, authorized);
    }

    /// @param lowLeafIndex The commitment's predecessor slot, from `registry.lowLeafIndexOf`.
    function revoke(uint256 revocationCommitment, uint256 lowLeafIndex) external onlyRevoker {
        REVOCATION.revoke(REGISTRY_ID, revocationCommitment, lowLeafIndex);
        revokedBy[revocationCommitment] = msg.sender;
    }

    /// @param lowLeafIndices From `registry.lowLeafIndicesOf`.
    function revokeMany(uint256[] calldata revocationCommitments, uint256[] calldata lowLeafIndices)
        external
        onlyRevoker
    {
        if (revocationCommitments.length != lowLeafIndices.length) revert LengthMismatch();

        REVOCATION.revokeMany(REGISTRY_ID, revocationCommitments, lowLeafIndices);
        for (uint256 i = 0; i < revocationCommitments.length; i++) {
            revokedBy[revocationCommitments[i]] = msg.sender;
        }
    }

    /// @param predecessorIndex From `registry.predecessorIndexOf`.
    function unrevoke(uint256 revocationCommitment, uint256 predecessorIndex)
        external
        onlyCommitmentRevoker(revocationCommitment)
    {
        REVOCATION.unrevoke(REGISTRY_ID, revocationCommitment, predecessorIndex);
        delete revokedBy[revocationCommitment];
    }

    function updateRevocationCommitment(
        uint256 oldRevocationCommitment,
        uint256 newRevocationCommitment,
        uint256 oldPredecessorIndex,
        uint256 newPredecessorIndex
    ) external onlyCommitmentRevoker(oldRevocationCommitment) {
        REVOCATION.updateRevocationCommitment(
            REGISTRY_ID, oldRevocationCommitment, newRevocationCommitment, oldPredecessorIndex, newPredecessorIndex
        );
        delete revokedBy[oldRevocationCommitment];
        revokedBy[newRevocationCommitment] = msg.sender;
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
