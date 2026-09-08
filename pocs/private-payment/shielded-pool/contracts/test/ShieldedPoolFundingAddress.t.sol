// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @dev Accepts a deposit proof only when the 4th public input is the expected funding address.
contract FundingCheckingVerifier is IVerifier {
    bytes32 public expectedFunding;

    function expectFunding(address funding) external {
        expectedFunding = bytes32(uint256(uint160(funding)));
    }

    function verifyDeposit(bytes calldata, bytes32[] calldata inputs) external view override returns (bool) {
        return inputs.length == 6 && inputs[3] == expectedFunding;
    }

    function verifyTransfer(bytes calldata, bytes32[] calldata) external pure override returns (bool) {
        return true;
    }

    function verifyWithdraw(bytes calldata, bytes32[] calldata) external pure override returns (bool) {
        return true;
    }
}

/// @title Funding-address binding (spec 2/SHIELDED-POOL 5.3)
/// @notice The pool pulls tokens only from the funding address bound into the proof, and the
/// funding address must be the caller. The circuit does not constrain the funding address, so
/// without the caller check an attested key holder could bind any address that holds an
/// outstanding approval and deposit against it.
contract ShieldedPoolFundingAddressTest is Test {
    ShieldedPool internal pool;
    FundingCheckingVerifier internal verifier;
    MockERC20 internal token;

    address internal depositor = address(0xD1);
    address internal relayer = address(0xE1);
    uint256 internal constant AMOUNT = 1000e6;

    function setUp() public {
        AttestationRegistry registry = new AttestationRegistry();
        verifier = new FundingCheckingVerifier();
        pool = new ShieldedPool(address(verifier), address(registry));

        token = new MockERC20("USD Coin", "USDC", 6);
        pool.addSupportedToken(address(token));
        token.mint(depositor, AMOUNT);
        vm.prank(depositor);
        token.approve(address(pool), type(uint256).max);
    }

    function test_fundingAddressSubmits_tokensPulledFromIt() public {
        verifier.expectFunding(depositor);

        vm.prank(depositor);
        pool.deposit("", bytes32(uint256(1)), address(token), AMOUNT, depositor, "");

        assertEq(token.balanceOf(depositor), 0, "funding address pays");
        assertEq(token.balanceOf(address(pool)), AMOUNT);
        assertEq(pool.getCommitmentCount(), 1);
    }

    /// @dev A third party with a valid proof of its own (the verifier accepts the bound funding
    /// address) must not be able to deposit against another address's outstanding approval.
    function test_thirdPartyCannotDepositAgainstOthersAllowance() public {
        verifier.expectFunding(depositor);

        vm.prank(relayer);
        vm.expectRevert(ShieldedPool.FundingAddressMismatch.selector);
        pool.deposit("", bytes32(uint256(1)), address(token), AMOUNT, depositor, "");

        assertEq(token.balanceOf(depositor), AMOUNT, "approval not spent");
        assertEq(pool.getCommitmentCount(), 0);
    }

    function test_proofForOtherFundingAddress_failsVerification() public {
        // Proof was made for `relayer` as funding address; the caller (depositor) presents a
        // different public input, so verification fails before any token movement.
        verifier.expectFunding(relayer);

        vm.prank(depositor);
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.deposit("", bytes32(uint256(1)), address(token), AMOUNT, depositor, "");
        assertEq(token.balanceOf(depositor), AMOUNT, "approval not spent");
    }

    function test_zeroFundingAddressReverts() public {
        verifier.expectFunding(address(0));
        vm.prank(depositor);
        vm.expectRevert(ShieldedPool.ZeroAddress.selector);
        pool.deposit("", bytes32(uint256(1)), address(token), AMOUNT, address(0), "");
    }
}
