// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {PublicInputs, DepositPublicInputs, TransferPublicInputs, WithdrawPublicInputs} from "../src/PublicInputs.sol";
import {MockFundToken} from "../src/mocks/MockFundToken.sol";

/// @dev Grumpkin's generator: a valid register-feed point `R` for tests.
uint256 constant GRUMPKIN_GX = 1;
uint256 constant GRUMPKIN_GY = 17631683881184975370165255887551781615748388533673675138860;

/// @notice Shared deployment for the pool tests: the mock fund token, the
///         registry with one attested batch, a mock verifier, and the pool
///         registered on the token as the SPEC requires.
abstract contract PoolTestBase is Test {
    ShieldedPool public pool;
    AttestationRegistry public registry;
    MockFundToken public token;
    MockCompositeVerifier public verifier;

    uint256 internal constant EPOCH_SECONDS = 86400;
    uint256 internal constant S = 1e18;

    // Grumpkin's generator, a valid register key.
    uint256 internal constant GX = 1;
    uint256 internal constant GY = 17631683881184975370165255887551781615748388533673675138860;
    bytes32 internal constant CLAIM_KEY_HASH = bytes32(uint256(0xc1a1));

    address internal timelock = address(0x71);
    address internal guardian = address(0x62);
    address internal agent = address(0xA6E7);
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    uint256 internal nextLeaf = 1;

    /// @dev The seed the transfer agent deposits in `setUp`, as at deployment:
    ///      one unit, so tests that need round totals deposit one less.
    uint64 internal constant SEED_UNITS = 1;

    function setUp() public virtual {
        vm.warp(1000 * EPOCH_SECONDS);

        token = new MockFundToken("Mock Fund Shares", "mMMF", address(this), 1e15);
        registry = new AttestationRegistry(EPOCH_SECONDS, 30, 3, 1, agent, timelock);
        verifier = new MockCompositeVerifier();
        pool = new ShieldedPool(_params());

        token.setAllowlisted(address(pool), true);
        token.setLimitExempt(address(pool), true);
        token.setAdminExempt(address(pool), true);
        token.setAllowlisted(alice, true);
        token.setAllowlisted(bob, true);
        token.setAllowlisted(agent, true);
        token.mint(alice, 1e13);
        vm.prank(alice);
        token.approve(address(pool), type(uint256).max);

        bytes32[] memory owners = new bytes32[](1);
        owners[0] = bytes32(uint256(0x0e1));
        uint64 expiresAt = uint64((pool.currentEpoch() + 30) * EPOCH_SECONDS);
        vm.prank(agent);
        registry.addAttestations(owners, expiresAt, 0);

        // As at deployment, the transfer agent seeds the pool: an empty pool
        // takes its first deposit from the agent only.
        token.mint(agent, 1e13);
        vm.prank(agent);
        token.approve(address(pool), type(uint256).max);
        _deposit(agent, SEED_UNITS);
    }

    function _params() internal view returns (ShieldedPool.ConstructorParams memory) {
        return ShieldedPool.ConstructorParams({
            token: address(token),
            attestationRegistry: address(registry),
            verifier: address(verifier),
            claimKeyHash: CLAIM_KEY_HASH,
            transferAgent: agent,
            registerKeyX: GX,
            registerKeyY: GY,
            epochSeconds: EPOCH_SECONDS,
            maxPauseEpochs: 14,
            pauseBudgetEpochs: 30,
            pauseWindowEpochs: 90,
            timelockController: timelock,
            guardian: guardian
        });
    }

    function _leaf() internal returns (bytes32) {
        return bytes32(nextLeaf++);
    }

    function _depositParams(bytes32 commitment, uint64 units)
        internal
        view
        returns (ShieldedPool.DepositParams memory p)
    {
        p.proof = "";
        p.commitment = commitment;
        p.units = units;
        p.attestationRoot = registry.attestationRoot();
        p.epoch = pool.currentEpoch();
        p.feedR = [GRUMPKIN_GX, GRUMPKIN_GY];
        p.feedCt = [uint256(21), 22, 23, 24, 25, 26, 27, 28];
        p.recipientPayload = "payload";
    }

    function _transferParams(bytes32 n0, bytes32 n1, bytes32 c0, bytes32 c1)
        internal
        view
        returns (ShieldedPool.TransferParams memory p)
    {
        p.proof = "";
        p.nullifier0 = n0;
        p.nullifier1 = n1;
        p.commitmentOut0 = c0;
        p.commitmentOut1 = c1;
        p.commitmentRoot = pool.commitmentRoot();
        p.attestationRoot = registry.attestationRoot();
        p.epoch = pool.currentEpoch();
        p.feedR = [GRUMPKIN_GX, GRUMPKIN_GY];
        p.feedCt = [uint256(31), 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46];
        p.recipientPayload = "payload";
    }

    function _withdrawParams(bytes32 nullifier, uint64 units, address recipient)
        internal
        view
        returns (ShieldedPool.WithdrawParams memory p)
    {
        p.proof = "";
        p.nullifier = nullifier;
        p.units = units;
        p.recipient = recipient;
        p.commitmentRoot = pool.commitmentRoot();
        p.attestationRoot = registry.attestationRoot();
        p.epoch = pool.currentEpoch();
    }

    /// @dev The public inputs the pool must hand the verifier for `p`, filling
    ///      the state-derived ones independently of the pool's own code.
    function _expectedDepositInputs(ShieldedPool.DepositParams memory p, address from)
        internal
        view
        returns (bytes32[] memory inputs)
    {
        inputs = new bytes32[](DepositPublicInputs.LENGTH);
        inputs[0] = p.commitment;
        inputs[1] = bytes32(uint256(uint160(address(token))));
        inputs[2] = bytes32(uint256(p.units));
        inputs[3] = bytes32(uint256(uint160(from)));
        inputs[4] = p.attestationRoot;
        inputs[5] = bytes32(registry.minAcceptedGeneration());
        inputs[6] = bytes32(p.epoch);
        inputs[7] = bytes32(block.chainid);
        inputs[8] = bytes32(uint256(uint160(address(pool))));
        inputs[9] = bytes32(pool.registerKeyX());
        inputs[10] = bytes32(pool.registerKeyY());
        inputs[11] = bytes32(p.feedR[0]);
        inputs[12] = bytes32(p.feedR[1]);
        for (uint256 i = 0; i < 8; i++) {
            inputs[13 + i] = bytes32(p.feedCt[i]);
        }
        inputs[21] = bytes32(uint256(keccak256(p.recipientPayload)) % PublicInputs.BN254_MODULUS);
    }

    function _expectedTransferInputs(ShieldedPool.TransferParams memory p)
        internal
        view
        returns (bytes32[] memory inputs)
    {
        inputs = new bytes32[](TransferPublicInputs.LENGTH);
        inputs[0] = p.nullifier0;
        inputs[1] = p.nullifier1;
        inputs[2] = p.commitmentOut0;
        inputs[3] = p.commitmentOut1;
        inputs[4] = p.commitmentRoot;
        inputs[5] = p.attestationRoot;
        inputs[6] = bytes32(registry.minAcceptedGeneration());
        inputs[7] = bytes32(p.epoch);
        inputs[8] = bytes32(block.chainid);
        inputs[9] = bytes32(uint256(uint160(address(pool))));
        inputs[10] = pool.claimKeyHash();
        inputs[11] = bytes32(pool.registerKeyX());
        inputs[12] = bytes32(pool.registerKeyY());
        inputs[13] = bytes32(p.feedR[0]);
        inputs[14] = bytes32(p.feedR[1]);
        for (uint256 i = 0; i < 16; i++) {
            inputs[15 + i] = bytes32(p.feedCt[i]);
        }
        inputs[31] = bytes32(uint256(keccak256(p.recipientPayload)) % PublicInputs.BN254_MODULUS);
    }

    function _expectedWithdrawInputs(ShieldedPool.WithdrawParams memory p)
        internal
        view
        returns (bytes32[] memory inputs)
    {
        inputs = new bytes32[](WithdrawPublicInputs.LENGTH);
        inputs[0] = p.nullifier;
        inputs[1] = bytes32(uint256(uint160(address(token))));
        inputs[2] = bytes32(uint256(p.units));
        inputs[3] = bytes32(uint256(uint160(p.recipient)));
        inputs[4] = p.commitmentRoot;
        inputs[5] = p.attestationRoot;
        inputs[6] = bytes32(registry.minAcceptedGeneration());
        inputs[7] = bytes32(p.epoch);
        inputs[8] = bytes32(block.chainid);
        inputs[9] = bytes32(uint256(uint160(address(pool))));
    }

    function _deposit(address from, uint64 units) internal returns (bytes32 commitment) {
        commitment = _leaf();
        ShieldedPool.DepositParams memory p = _depositParams(commitment, units);
        vm.prank(from);
        pool.deposit(p);
    }

    function _withdraw(uint64 units, address recipient) internal returns (bytes32 nullifier) {
        nullifier = _leaf();
        pool.withdraw(_withdrawParams(nullifier, units, recipient));
    }

    /// @dev Mints `rateWad` of the pool's balance to it, as a daily reinvestment.
    function _reinvest(uint256 rateWad) internal {
        address[] memory holders = new address[](1);
        holders[0] = address(pool);
        token.reinvest(holders, rateWad);
    }
}
