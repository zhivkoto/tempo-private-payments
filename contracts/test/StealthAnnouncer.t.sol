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

    function test_transferOwnership() public {
        vm.prank(deployer);
        announcer.transferOwnership(alice);
        assertEq(announcer.owner(), alice);

        // Old owner can no longer call
        vm.prank(deployer);
        vm.expectRevert("StealthAnnouncer: not owner");
        announcer.setAnnouncementFee(0);

        // New owner can
        vm.prank(alice);
        announcer.setAnnouncementFee(0);
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
}
