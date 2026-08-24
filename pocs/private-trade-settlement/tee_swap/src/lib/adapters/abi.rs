#![allow(clippy::too_many_arguments)]

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IPrivateUTXO {
        function commitmentRoot() external view returns (bytes32);
        function nullifiers(bytes32 nullifier) external view returns (bool);

        function fund(bytes32 commitment) external;

        function transfer(
            bytes calldata proof,
            bytes32 nullifier,
            bytes32 root,
            bytes32 newCommitment,
            uint256 timeout,
            bytes32 pkStealth,
            bytes32 hSwap,
            bytes32 hR,
            bytes32 hMeta,
            bytes32 hEnc
        ) external;

        event SwapNoteLocked(
            bytes32 indexed commitment,
            uint256 timeout,
            bytes32 pkStealth,
            bytes32 hSwap,
            bytes32 hR,
            bytes32 hMeta,
            bytes32 hEnc
        );

        event NoteCreated(bytes32 indexed commitment);

        event NoteSpent(bytes32 indexed nullifier);
    }

    #[sol(rpc)]
    interface ITeeLock {
        function announcements(bytes32 swapId) external view returns (
            bool revealed,
            bytes32 ephemeralKeyA,
            bytes32 ephemeralKeyB,
            bytes32 encryptedSaltA,
            bytes32 encryptedSaltB
        );

        function announceSwap(
            bytes32 swapId,
            bytes32 ephemeralKeyA,
            bytes32 ephemeralKeyB,
            bytes32 encryptedSaltA,
            bytes32 encryptedSaltB
        ) external;

        event SwapRevealed(bytes32 indexed swapId);
    }
}
