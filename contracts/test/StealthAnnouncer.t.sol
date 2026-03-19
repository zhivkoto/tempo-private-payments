// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/StealthAnnouncer.sol";
import "../src/interfaces/IStealthAnnouncer.sol";

/// @dev Mock TIP-20 token for testing fee collection
contract MockTIP20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "insufficient balance");
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        return true;
    }
}

contract StealthAnnouncerTest is Test {
    StealthAnnouncer public announcer;
    MockTIP20 public token;

    address public deployer = makeAddr("deployer");
    address public alice = makeAddr("alice");
    address public treasury = makeAddr("treasury");
    address public stealthAddr = makeAddr("stealthAddr");

    uint256 public constant FEE = 1000; // 1000 base units

    // Valid compressed secp256k1 ephemeral pubkey (33 bytes)
    bytes public ephemeralPubKey = abi.encodePacked(
        bytes1(0x02),
        bytes32(0x0000000000000000000000000000000000000000000000000000000000000001)
    );

    function setUp() public {
        token = new MockTIP20();

        vm.prank(deployer);
        announcer = new StealthAnnouncer(address(token), FEE, treasury);

        // Fund alice and approve
        token.mint(alice, 1_000_000);
        vm.prank(alice);
        token.approve(address(announcer), type(uint256).max);
    }

    // ========== Existing tests ==========

    function test_announce_emitsEvent() public {
        vm.expectEmit(true, true, true, true);
        emit IStealthAnnouncer.Announcement(
            1,
            stealthAddr,
            alice,
            ephemeralPubKey,
            0x42,
            bytes("payment-ref")
        );

        vm.prank(alice);
        announcer.announce(1, stealthAddr, ephemeralPubKey, 0x42, bytes("payment-ref"));
    }

    function test_announce_collectsFee() public {
        uint256 aliceBefore = token.balanceOf(alice);
        uint256 treasuryBefore = token.balanceOf(treasury);

        vm.prank(alice);
        announcer.announce(1, stealthAddr, ephemeralPubKey, 0x42, bytes(""));

        assertEq(token.balanceOf(alice), aliceBefore - FEE);
        assertEq(token.balanceOf(treasury), treasuryBefore + FEE);
    }

    function test_announce_zeroFee() public {
        vm.prank(deployer);
        announcer.setAnnouncementFee(0);

        // Should succeed without any transfer
        vm.prank(alice);
        announcer.announce(1, stealthAddr, ephemeralPubKey, 0x42, bytes(""));
    }

    function test_revert_zeroStealthAddress() public {
        vm.prank(alice);
        vm.expectRevert("StealthAnnouncer: zero stealth address");
        announcer.announce(1, address(0), ephemeralPubKey, 0x42, bytes(""));
    }

    function test_revert_invalidEphemeralPubKeyLength() public {
        vm.prank(alice);
        vm.expectRevert("StealthAnnouncer: invalid ephemeral pubkey length");
        announcer.announce(1, stealthAddr, bytes("short"), 0x42, bytes(""));
    }

    function test_revert_insufficientFeeAllowance() public {
        address bob = makeAddr("bob");
        token.mint(bob, 1_000_000);
        // bob does NOT approve the announcer

        vm.prank(bob);
        vm.expectRevert("StealthAnnouncer: fee transfer failed");
        announcer.announce(1, stealthAddr, ephemeralPubKey, 0x42, bytes(""));
    }

    function test_setAnnouncementFee_onlyOwner() public {
        vm.prank(deployer);
        announcer.setAnnouncementFee(2000);
        assertEq(announcer.announcementFee(), 2000);

        vm.prank(alice);
        vm.expectRevert("StealthAnnouncer: not owner");
        announcer.setAnnouncementFee(9999);
    }

    function test_setTreasury_onlyOwner() public {
        address newTreasury = makeAddr("newTreasury");

        vm.prank(deployer);
        announcer.setTreasury(newTreasury);
        assertEq(announcer.treasury(), newTreasury);

        vm.prank(alice);
        vm.expectRevert("StealthAnnouncer: not owner");
        announcer.setTreasury(newTreasury);
    }

    function test_revert_setTreasury_zero() public {
        vm.prank(deployer);
        vm.expectRevert("StealthAnnouncer: zero treasury");
        announcer.setTreasury(address(0));
    }

    function test_multipleAnnouncements() public {
        // Verify multiple announcements work and fees accumulate
        vm.startPrank(alice);
        announcer.announce(1, stealthAddr, ephemeralPubKey, 0x01, bytes("ref1"));
        announcer.announce(1, makeAddr("stealth2"), ephemeralPubKey, 0x02, bytes("ref2"));
        announcer.announce(1, makeAddr("stealth3"), ephemeralPubKey, 0xFF, bytes("ref3"));
        vm.stopPrank();

        assertEq(token.balanceOf(treasury), FEE * 3);
    }

    // ========== M-1: Two-step ownership transfer tests ==========

    function test_transferOwnership_twoStep() public {
        address newOwner = makeAddr("newOwner");

        // Step 1: Current owner initiates transfer
        vm.prank(deployer);
        announcer.transferOwnership(newOwner);

        // Owner should NOT have changed yet
        assertEq(announcer.owner(), deployer);
        assertEq(announcer.pendingOwner(), newOwner);

        // Step 2: New owner accepts
        vm.prank(newOwner);
        announcer.acceptOwnership();

        assertEq(announcer.owner(), newOwner);
        assertEq(announcer.pendingOwner(), address(0));
    }

    function test_transferOwnership_emitsStartedEvent() public {
        address newOwner = makeAddr("newOwner");

        vm.expectEmit(true, true, false, true);
        emit IStealthAnnouncer.OwnershipTransferStarted(deployer, newOwner);

        vm.prank(deployer);
        announcer.transferOwnership(newOwner);
    }

    function test_acceptOwnership_emitsTransferredEvent() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(deployer);
        announcer.transferOwnership(newOwner);

        vm.expectEmit(true, true, false, true);
        emit IStealthAnnouncer.OwnershipTransferred(deployer, newOwner);

        vm.prank(newOwner);
        announcer.acceptOwnership();
    }

    function test_revert_acceptOwnership_notPending() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(deployer);
        announcer.transferOwnership(newOwner);

        // Random address tries to accept
        vm.prank(alice);
        vm.expectRevert("StealthAnnouncer: not pending owner");
        announcer.acceptOwnership();
    }

    function test_revert_acceptOwnership_noPending() public {
        // No transfer initiated — pendingOwner is address(0)
        vm.prank(alice);
        vm.expectRevert("StealthAnnouncer: not pending owner");
        announcer.acceptOwnership();
    }

    function test_transferOwnership_revert_zeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert("StealthAnnouncer: zero owner");
        announcer.transferOwnership(address(0));
    }

    function test_transferOwnership_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert("StealthAnnouncer: not owner");
        announcer.transferOwnership(alice);
    }

    function test_transferOwnership_oldOwnerLosesAccess() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(deployer);
        announcer.transferOwnership(newOwner);

        vm.prank(newOwner);
        announcer.acceptOwnership();

        // Old owner can no longer call admin functions
        vm.prank(deployer);
        vm.expectRevert("StealthAnnouncer: not owner");
        announcer.setAnnouncementFee(0);

        // New owner can
        vm.prank(newOwner);
        announcer.setAnnouncementFee(0);
    }

    function test_transferOwnership_overwritePending() public {
        address newOwner1 = makeAddr("newOwner1");
        address newOwner2 = makeAddr("newOwner2");

        vm.prank(deployer);
        announcer.transferOwnership(newOwner1);

        // Owner changes their mind, initiates new transfer
        vm.prank(deployer);
        announcer.transferOwnership(newOwner2);

        assertEq(announcer.pendingOwner(), newOwner2);

        // First candidate can no longer accept
        vm.prank(newOwner1);
        vm.expectRevert("StealthAnnouncer: not pending owner");
        announcer.acceptOwnership();

        // Second candidate can
        vm.prank(newOwner2);
        announcer.acceptOwnership();
        assertEq(announcer.owner(), newOwner2);
    }

    // ========== M-2: Admin state change events tests ==========

    function test_setAnnouncementFee_emitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit IStealthAnnouncer.AnnouncementFeeUpdated(FEE, 2000);

        vm.prank(deployer);
        announcer.setAnnouncementFee(2000);
    }

    function test_setTreasury_emitsEvent() public {
        address newTreasury = makeAddr("newTreasury");

        vm.expectEmit(true, true, false, true);
        emit IStealthAnnouncer.TreasuryUpdated(treasury, newTreasury);

        vm.prank(deployer);
        announcer.setTreasury(newTreasury);
    }

    function test_constructor_emitsOwnershipTransferred() public {
        vm.expectEmit(true, true, false, true);
        emit IStealthAnnouncer.OwnershipTransferred(address(0), address(this));

        new StealthAnnouncer(address(token), FEE, treasury);
    }

    // ========== M-3: Metadata size cap tests ==========

    function test_maxMetadataSize_default() public view {
        assertEq(announcer.maxMetadataSize(), 1024);
    }

    function test_announce_metadataAtLimit() public {
        bytes memory metadata = new bytes(1024);
        // Fill with non-zero data
        for (uint256 i = 0; i < 1024; i++) {
            metadata[i] = 0x42;
        }

        vm.prank(alice);
        announcer.announce(1, stealthAddr, ephemeralPubKey, 0x42, metadata);
    }

    function test_revert_announce_metadataTooLarge() public {
        bytes memory metadata = new bytes(1025);

        vm.prank(alice);
        vm.expectRevert("StealthAnnouncer: metadata too large");
        announcer.announce(1, stealthAddr, ephemeralPubKey, 0x42, metadata);
    }

    function test_setMaxMetadataSize() public {
        vm.prank(deployer);
        announcer.setMaxMetadataSize(2048);
        assertEq(announcer.maxMetadataSize(), 2048);

        // Now 1025 bytes should be fine
        bytes memory metadata = new bytes(1025);
        vm.prank(alice);
        announcer.announce(1, stealthAddr, ephemeralPubKey, 0x42, metadata);
    }

    function test_setMaxMetadataSize_emitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit IStealthAnnouncer.MaxMetadataSizeUpdated(1024, 2048);

        vm.prank(deployer);
        announcer.setMaxMetadataSize(2048);
    }

    function test_setMaxMetadataSize_onlyOwner() public {
        vm.prank(alice);
        vm.expectRevert("StealthAnnouncer: not owner");
        announcer.setMaxMetadataSize(2048);
    }

    function test_setMaxMetadataSize_zero_blocksMetadata() public {
        vm.prank(deployer);
        announcer.setMaxMetadataSize(0);

        // Empty metadata should still work
        vm.prank(alice);
        announcer.announce(1, stealthAddr, ephemeralPubKey, 0x42, bytes(""));

        // Any metadata should fail
        vm.prank(alice);
        vm.expectRevert("StealthAnnouncer: metadata too large");
        announcer.announce(1, stealthAddr, ephemeralPubKey, 0x42, bytes("x"));
    }
}
