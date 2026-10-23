// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Indexes into the deposit circuit's 22 public inputs. Order MUST match
///         `circuits/deposit/src/main.nr` `main(...)` parameter order, arrays
///         flattened in place.
library DepositPublicInputs {
    uint256 internal constant COMMITMENT = 0;
    uint256 internal constant TOKEN = 1;
    uint256 internal constant UNITS = 2;
    uint256 internal constant FUNDING_ADDRESS = 3;
    uint256 internal constant ATTESTATION_ROOT = 4;
    uint256 internal constant MIN_ACCEPTED_GENERATION = 5;
    uint256 internal constant EPOCH = 6;
    uint256 internal constant CHAIN_ID = 7;
    uint256 internal constant POOL = 8;
    uint256 internal constant REGISTER_KEY_X = 9;
    uint256 internal constant REGISTER_KEY_Y = 10;
    uint256 internal constant FEED_R_X = 11;
    uint256 internal constant FEED_R_Y = 12;
    /// @dev Eight elements: the encrypted (token, units, owner, salt, lock,
    ///      reason, release_after, claim_party).
    uint256 internal constant FEED_CT = 13;
    uint256 internal constant PAYLOAD_COMMITMENT = 21;
    uint256 internal constant LENGTH = 22;
}

/// @notice Indexes into the transfer circuit's 32 public inputs. Order MUST match
///         `circuits/transfer/src/main.nr` `main(...)` parameter order, arrays
///         flattened in place.
library TransferPublicInputs {
    uint256 internal constant NULLIFIER_0 = 0;
    uint256 internal constant NULLIFIER_1 = 1;
    uint256 internal constant COMMITMENT_OUT_0 = 2;
    uint256 internal constant COMMITMENT_OUT_1 = 3;
    uint256 internal constant COMMITMENT_ROOT = 4;
    uint256 internal constant ATTESTATION_ROOT = 5;
    uint256 internal constant MIN_ACCEPTED_GENERATION = 6;
    uint256 internal constant EPOCH = 7;
    uint256 internal constant CHAIN_ID = 8;
    uint256 internal constant POOL = 9;
    uint256 internal constant CLAIM_KEY_HASH = 10;
    uint256 internal constant REGISTER_KEY_X = 11;
    uint256 internal constant REGISTER_KEY_Y = 12;
    uint256 internal constant FEED_R_X = 13;
    uint256 internal constant FEED_R_Y = 14;
    /// @dev Sixteen elements: output 0's eight fields, then output 1's.
    uint256 internal constant FEED_CT = 15;
    uint256 internal constant PAYLOAD_COMMITMENT = 31;
    uint256 internal constant LENGTH = 32;
}

/// @notice Indexes into the withdraw circuit's 10 public inputs. Order MUST
///         match `circuits/withdraw/src/main.nr` `main(...)` parameter order.
library WithdrawPublicInputs {
    uint256 internal constant NULLIFIER = 0;
    uint256 internal constant TOKEN = 1;
    uint256 internal constant UNITS = 2;
    uint256 internal constant RECIPIENT = 3;
    uint256 internal constant COMMITMENT_ROOT = 4;
    uint256 internal constant ATTESTATION_ROOT = 5;
    uint256 internal constant MIN_ACCEPTED_GENERATION = 6;
    uint256 internal constant EPOCH = 7;
    uint256 internal constant CHAIN_ID = 8;
    uint256 internal constant POOL = 9;
    uint256 internal constant LENGTH = 10;
}

/// @notice Shared field arithmetic for every entry point's public inputs.
library PublicInputs {
    uint256 internal constant BN254_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    error NonCanonicalInput();

    /// @notice `2^256 / p` is about 5.29, so a prover submitting `n + p` presents the
    ///         same field element to the verifier and an unseen key to the
    ///         `nullifiers` mapping, which would let one note be spent twice.
    function requireCanonical(bytes32[] memory inputs) internal pure {
        for (uint256 i = 0; i < inputs.length; i++) {
            if (uint256(inputs[i]) >= BN254_MODULUS) revert NonCanonicalInput();
        }
    }

    /// @notice keccak256 of the recipient payload, reduced into the field, so the
    ///         payload the pool emits is the one the proof was built with.
    function payloadCommitment(bytes calldata payload) internal pure returns (bytes32) {
        return bytes32(uint256(keccak256(payload)) % BN254_MODULUS);
    }

    /// @notice Whether (x, y) is on Grumpkin, y^2 = x^3 - 17 over the BN254 scalar
    ///         field. The register key must be, or no deposit or transfer can prove.
    function onGrumpkin(uint256 x, uint256 y) internal pure returns (bool) {
        uint256 p = BN254_MODULUS;
        if (x >= p || y >= p) return false;
        uint256 rhs = addmod(mulmod(mulmod(x, x, p), x, p), p - 17, p);
        return mulmod(y, y, p) == rhs;
    }
}
