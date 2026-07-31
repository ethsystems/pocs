// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IAttestationRegistry
/// @notice The surface ShieldedPool reads. The reference is one-directional: the
///         pool reads the registry, never the reverse.
interface IAttestationRegistry {
    /// @notice The current attestation Merkle root
    function attestationRoot() external view returns (bytes32);

    /// @notice Whether `root` sits in the registry's historical attestation-root ring
    function isKnownAttestationRoot(bytes32 root) external view returns (bool);

    /// @notice The current attester revocation tree root
    function attesterRevocationRoot() external view returns (bytes32);

    /// @notice The oldest attestation `generation` still accepted
    function minAcceptedGeneration() external view returns (uint256);

    /// @notice The epoch length this registry was configured with
    function EPOCH_SECONDS() external view returns (uint256);
}
