// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Indexes into the deposit circuit's 13 public inputs. Order MUST match
///         `circuits/deposit/src/main.nr` `main(...)` parameter order.
library DepositPublicInputs {
    uint256 internal constant COMMITMENT = 0;
    uint256 internal constant TOKEN = 1;
    uint256 internal constant AMOUNT = 2;
    uint256 internal constant ATTESTATION_ROOT = 3;
    uint256 internal constant VELOCITY_NULLIFIER = 4;
    uint256 internal constant COMPLIANCE_COMMITMENT_OUT = 5;
    uint256 internal constant EPOCH = 6;
    uint256 internal constant EPOCH_SECONDS = 7;
    uint256 internal constant POLICY_SOURCE_HASH = 8;
    uint256 internal constant COMMITMENT_ROOT = 9;
    uint256 internal constant ATTESTER_REVOCATION_ROOT = 10;
    uint256 internal constant MIN_ACCEPTED_GENERATION = 11;
    uint256 internal constant PAYLOAD_COMMITMENT = 12;
    uint256 internal constant LENGTH = 13;
}

/// @notice Indexes into the transfer circuit's 14 public inputs. Order MUST match
///         `circuits/transfer/src/main.nr` `main(...)` parameter order.
///         `COMPLIANCE_COMMITMENT_OUT` sits at 6 here, at 5 on deposit; that
///         asymmetry is fixed by the SPEC and MUST be preserved.
library TransferPublicInputs {
    uint256 internal constant NULLIFIER_0 = 0;
    uint256 internal constant NULLIFIER_1 = 1;
    uint256 internal constant COMMITMENT_OUT_0 = 2;
    uint256 internal constant COMMITMENT_OUT_1 = 3;
    uint256 internal constant COMMITMENT_ROOT = 4;
    uint256 internal constant VELOCITY_NULLIFIER = 5;
    uint256 internal constant COMPLIANCE_COMMITMENT_OUT = 6;
    uint256 internal constant EPOCH = 7;
    uint256 internal constant EPOCH_SECONDS = 8;
    uint256 internal constant POLICY_SOURCE_HASH = 9;
    uint256 internal constant ATTESTATION_ROOT = 10;
    uint256 internal constant ATTESTER_REVOCATION_ROOT = 11;
    uint256 internal constant MIN_ACCEPTED_GENERATION = 12;
    uint256 internal constant PAYLOAD_COMMITMENT = 13;
    uint256 internal constant LENGTH = 14;
}

/// @notice Indexes into the gated withdraw circuit's 14 public inputs. Order MUST
///         match `circuits/withdraw/src/main.nr` `main(...)` parameter order.
library WithdrawPublicInputs {
    uint256 internal constant NULLIFIER = 0;
    uint256 internal constant TOKEN = 1;
    uint256 internal constant AMOUNT = 2;
    uint256 internal constant RECIPIENT = 3;
    uint256 internal constant COMMITMENT_ROOT = 4;
    uint256 internal constant VELOCITY_NULLIFIER = 5;
    uint256 internal constant COMPLIANCE_COMMITMENT_OUT = 6;
    uint256 internal constant EPOCH = 7;
    uint256 internal constant EPOCH_SECONDS = 8;
    uint256 internal constant POLICY_SOURCE_HASH = 9;
    uint256 internal constant ATTESTATION_ROOT = 10;
    uint256 internal constant ATTESTER_REVOCATION_ROOT = 11;
    uint256 internal constant MIN_ACCEPTED_GENERATION = 12;
    uint256 internal constant PAYLOAD_COMMITMENT = 13;
    uint256 internal constant LENGTH = 14;
}

/// @notice Indexes into the ungated withdraw circuit's 5 public inputs, the
///         parent's unchanged. Order MUST match
///         `circuits/withdraw_ungated/src/main.nr` `main(...)` parameter order.
library UngatedWithdrawPublicInputs {
    uint256 internal constant NULLIFIER = 0;
    uint256 internal constant TOKEN = 1;
    uint256 internal constant AMOUNT = 2;
    uint256 internal constant RECIPIENT = 3;
    uint256 internal constant COMMITMENT_ROOT = 4;
    uint256 internal constant LENGTH = 5;
}

/// @notice Shared canonicality check for every entry point's public inputs.
library PublicInputs {
    uint256 internal constant BN254_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    error NonCanonicalInput();

    /// @notice `2^256 / p` is about 5.29, so a prover submitting `vn + p` presents the
    ///         same field element to the verifier and an unseen key to the
    ///         `nullifiers` mapping, forking a compliance chain at a repeated `seq`.
    function requireCanonical(bytes32[] memory inputs) internal pure {
        for (uint256 i = 0; i < inputs.length; i++) {
            if (uint256(inputs[i]) >= BN254_MODULUS) revert NonCanonicalInput();
        }
    }
}
