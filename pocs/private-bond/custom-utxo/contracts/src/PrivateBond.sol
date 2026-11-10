// SPDX-License-Identifier: MIT
pragma solidity >=0.8.21;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./Verifier.sol";
import "./PoseidonT3.sol";

/// @notice Indexes into the circuit's 8 public inputs. Order MUST match
///         `circuits/src/main.nr` `main(...)` parameter order, with the
///         returned redeem flag last.
library BondPublicInputs {
    uint256 internal constant ROOT = 0;
    uint256 internal constant NULLIFIER_0 = 1;
    uint256 internal constant NULLIFIER_1 = 2;
    uint256 internal constant COMMITMENT_0 = 3;
    uint256 internal constant COMMITMENT_1 = 4;
    uint256 internal constant INPUT_MATURITY_DATE = 5;
    uint256 internal constant OUTPUT_MATURITY_DATE = 6;
    uint256 internal constant IS_REDEEM = 7;
    uint256 internal constant LENGTH = 8;
}

contract PrivateBond is Ownable {
    HonkVerifier public verifier;

    /// @notice Bond identifier for reconciliation (ISIN hash, CUSIP, or BDT hash)
    bytes32 public bondId;

    bytes32[] public commitments;

    mapping(bytes32 => bool) public knownRoots;
    mapping(bytes32 => bool) public nullifiers;

    constructor(bytes32 _bondId, address _verifier, address initialOwner) Ownable(initialOwner) {
        bondId = _bondId;
        verifier = HonkVerifier(_verifier);
    }

    // Transfer a bond ownership
    // maturityDate is a public input of the proof, so a matured bond cannot move
    function transfer(
        bytes calldata proof,
        bytes32 root,
        bytes32[2] calldata nullifiersIn,
        bytes32[2] calldata commitmentsOut,
        bytes32 maturityDate
    ) external {
        require(block.timestamp < uint256(maturityDate), "Bond already matured");
        require(knownRoots[root], "Invalid Merkle Root");
        require(!nullifiers[nullifiersIn[0]], "Note 0 already spent");
        require(!nullifiers[nullifiersIn[1]], "Note 1 already spent");
        require(nullifiersIn[0] != nullifiersIn[1], "Identical nullifiers");

        bytes32[] memory publicInputs = _publicInputs(root, nullifiersIn, commitmentsOut, maturityDate, false);

        require(verifier.verify(proof, publicInputs), "Invalid Transfer Proof");

        nullifiers[nullifiersIn[0]] = true;
        nullifiers[nullifiersIn[1]] = true;

        commitments.push(commitmentsOut[0]);
        commitments.push(commitmentsOut[1]);

        bytes32 newRoot = buildMerkleRoot();
        knownRoots[newRoot] = true;
    }

    // Minting a new bond
    function mint(bytes32 _commitment) external onlyOwner {
        commitments.push(_commitment);
        
        bytes32 newRoot = buildMerkleRoot();
        knownRoots[newRoot] = true;
    }

    // Enables minting all the bonds at once
    function mintBatch(bytes32[] memory _commitments) external onlyOwner {
        for (uint32 i = 0; i < _commitments.length; i++) {
            commitments.push(_commitments[i]);
        }
        bytes32 newRoot = buildMerkleRoot();
        knownRoots[newRoot] = true;
    }

    // Build the merkle root to update contract state
    function buildMerkleRoot() public view returns (bytes32) {
        require(commitments.length > 0, "No commitments provided");
        
        bytes32[] memory currentLevel = commitments;
        
        while (currentLevel.length > 1) {
            bytes32[] memory nextLevel = new bytes32[]((currentLevel.length + 1) / 2);
            
            for (uint32 i = 0; i < currentLevel.length; i += 2) {
                bytes32 left = currentLevel[i];
                bytes32 right = (i + 1 < currentLevel.length) ? currentLevel[i + 1] : left;
                
                nextLevel[i / 2] = poseidonHash(left, right);
            }
            
            currentLevel = nextLevel;
        }
        
        return currentLevel[0];
    }

    function poseidonHash(bytes32 _left, bytes32 _right) internal pure returns (bytes32) {
        uint hash = PoseidonT3.hash([uint256(_left), uint256(_right)]);
        return bytes32(hash);
    }

    // Public inputs in circuit order, for the functions that assemble them.
    // The circuit forces the input and output maturity dates to be equal.
    function _publicInputs(
        bytes32 root,
        bytes32[2] calldata nullifiersIn,
        bytes32[2] calldata commitmentsOut,
        bytes32 maturityDate,
        bool isRedeem
    ) internal pure returns (bytes32[] memory publicInputs) {
        publicInputs = new bytes32[](BondPublicInputs.LENGTH);
        publicInputs[BondPublicInputs.ROOT] = root;
        publicInputs[BondPublicInputs.NULLIFIER_0] = nullifiersIn[0];
        publicInputs[BondPublicInputs.NULLIFIER_1] = nullifiersIn[1];
        publicInputs[BondPublicInputs.COMMITMENT_0] = commitmentsOut[0];
        publicInputs[BondPublicInputs.COMMITMENT_1] = commitmentsOut[1];
        publicInputs[BondPublicInputs.INPUT_MATURITY_DATE] = maturityDate;
        publicInputs[BondPublicInputs.OUTPUT_MATURITY_DATE] = maturityDate;
        // Circuit returns true (1) when output values sum to 0 (redemption)
        publicInputs[BondPublicInputs.IS_REDEEM] = isRedeem ? bytes32(uint256(1)) : bytes32(0);
    }

    // Action of burning notes to redeem cash off-chain from the issuer
    // Uses same JoinSplit proof structure as transfer, but with output values = 0.
    // inputMaturityDate and the redeem flag are public inputs, so the proof binds both checks.
    function burn(
        bytes calldata proof,
        bytes32 root,
        bytes32[2] calldata nullifiersIn,
        bytes32[2] calldata commitmentsOut,
        bytes32 inputMaturityDate
    ) external {
        require(knownRoots[root], "Invalid Merkle Root");
        require(!nullifiers[nullifiersIn[0]], "Note 0 already spent");
        require(!nullifiers[nullifiersIn[1]], "Note 1 already spent");
        require(nullifiersIn[0] != nullifiersIn[1], "Identical nullifiers");
        require(block.timestamp >= uint256(inputMaturityDate), "Bond not at maturity yet");

        bytes32[] memory publicInputs = _publicInputs(root, nullifiersIn, commitmentsOut, inputMaturityDate, true);

        require(verifier.verify(proof, publicInputs), "Invalid Burn Proof");

        nullifiers[nullifiersIn[0]] = true;
        nullifiers[nullifiersIn[1]] = true;

        // For burn, we still add commitments (value=0 notes) to maintain tree structure
        commitments.push(commitmentsOut[0]);
        commitments.push(commitmentsOut[1]);

        bytes32 newRoot = buildMerkleRoot();
        knownRoots[newRoot] = true;
    }

    // Don't need to check KYC for now as trusted relayer will be the caller 
    function atomicSwap(
        bytes calldata proofA,
        bytes32[] calldata publicInputsA,

        bytes calldata proofB,
        bytes32[] calldata publicInputsB
    ) external onlyOwner {
        require(
            publicInputsA.length == BondPublicInputs.LENGTH && publicInputsB.length == BondPublicInputs.LENGTH,
            "Wrong public input count"
        );
        require(
            block.timestamp < uint256(publicInputsA[BondPublicInputs.INPUT_MATURITY_DATE]), "Bond A already matured"
        );
        require(
            block.timestamp < uint256(publicInputsB[BondPublicInputs.INPUT_MATURITY_DATE]), "Bond B already matured"
        );
        // Each leg must hand over value: a redemption proof (all outputs zero) is not a swap leg
        require(publicInputsA[BondPublicInputs.IS_REDEEM] == bytes32(0), "Swap leg A is a redemption");
        require(publicInputsB[BondPublicInputs.IS_REDEEM] == bytes32(0), "Swap leg B is a redemption");

        require(verifier.verify(proofA, publicInputsA), "Invalid Transfer Proof A");
        require(verifier.verify(proofB, publicInputsB), "Invalid Transfer Proof B");

        require(knownRoots[publicInputsA[BondPublicInputs.ROOT]], "Invalid Merkle Root A");
        require(knownRoots[publicInputsB[BondPublicInputs.ROOT]], "Invalid Merkle Root B");

        // Each proof spends two inputs; all four nullifiers must be unspent and distinct
        bytes32 nullifierA0 = publicInputsA[BondPublicInputs.NULLIFIER_0];
        bytes32 nullifierA1 = publicInputsA[BondPublicInputs.NULLIFIER_1];
        bytes32 nullifierB0 = publicInputsB[BondPublicInputs.NULLIFIER_0];
        bytes32 nullifierB1 = publicInputsB[BondPublicInputs.NULLIFIER_1];
        require(!nullifiers[nullifierA0] && !nullifiers[nullifierA1], "Note A already spent");
        require(!nullifiers[nullifierB0] && !nullifiers[nullifierB1], "Note B already spent");
        require(
            nullifierA0 != nullifierA1 && nullifierB0 != nullifierB1 && nullifierA0 != nullifierB0
                && nullifierA0 != nullifierB1 && nullifierA1 != nullifierB0 && nullifierA1 != nullifierB1,
            "Identical nullifiers"
        );

        nullifiers[nullifierA0] = true;
        nullifiers[nullifierA1] = true;
        nullifiers[nullifierB0] = true;
        nullifiers[nullifierB1] = true;

        commitments.push(publicInputsA[BondPublicInputs.COMMITMENT_0]);
        commitments.push(publicInputsA[BondPublicInputs.COMMITMENT_1]);
        commitments.push(publicInputsB[BondPublicInputs.COMMITMENT_0]);
        commitments.push(publicInputsB[BondPublicInputs.COMMITMENT_1]);

        // Update root
        bytes32 newRoot = buildMerkleRoot();
        knownRoots[newRoot] = true;
    }
}