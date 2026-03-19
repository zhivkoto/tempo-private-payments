// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/StealthRegistry.sol";
import "../src/interfaces/IStealthRegistry.sol";

contract StealthRegistryTest is Test {
    StealthRegistry public registry;
    address public deployer = makeAddr("deployer");
    address public alice = makeAddr("alice");

    // Valid scheme 1 meta-address: two compressed secp256k1 pubkeys (33 + 33 = 66 bytes)
    bytes public validMetaAddress = abi.encodePacked(
        // spending pubkey (33 bytes, starts with 0x02)
        bytes1(0x02), bytes32(0x0000000000000000000000000000000000000000000000000000000000000001),
        // viewing pubkey (33 bytes, starts with 0x03)
        bytes1(0x03), bytes32(0x0000000000000000000000000000000000000000000000000000000000000002)
    );

    function setUp() public {
        vm.prank(deployer);
        registry = new StealthRegistry();
    }

    // ========== Existing tests ==========

    function test_registerAndRetrieve() public {
        vm.prank(alice);
        registry.registerStealthMetaAddress(1, validMetaAddress);

        bytes memory retrieved = registry.stealthMetaAddressOf(alice, 1);
        assertEq(keccak256(retrieved), keccak256(validMetaAddress));
    }

    function test_emitsEvent() public {
        vm.expectEmit(true, true, false, true);
        emit IStealthRegistry.StealthMetaAddressSet(alice, 1, validMetaAddress);

        vm.prank(alice);
        registry.registerStealthMetaAddress(1, validMetaAddress);
    }

    function test_overwrite() public {
        vm.prank(alice);
        registry.registerStealthMetaAddress(1, validMetaAddress);

        // New meta-address (different bytes)
        bytes memory newMeta = abi.encodePacked(
            bytes1(0x02), bytes32(0x0000000000000000000000000000000000000000000000000000000000000099),
            bytes1(0x03), bytes32(0x0000000000000000000000000000000000000000000000000000000000000088)
        );

        vm.prank(alice);
        registry.registerStealthMetaAddress(1, newMeta);

        bytes memory retrieved = registry.stealthMetaAddressOf(alice, 1);
        assertEq(keccak256(retrieved), keccak256(newMeta));
    }

    function test_revert_zeroSchemeId() public {
        vm.prank(alice);
        vm.expectRevert("StealthRegistry: invalid scheme ID");
        registry.registerStealthMetaAddress(0, validMetaAddress);
    }

    function test_revert_emptyMetaAddress() public {
        vm.prank(alice);
        vm.expectRevert("StealthRegistry: empty meta-address");
        registry.registerStealthMetaAddress(1, "");
    }

    function test_revert_scheme1_wrongLength() public {
        vm.prank(alice);
        vm.expectRevert("StealthRegistry: scheme 1 requires 66 bytes (two compressed secp256k1 pubkeys)");
        registry.registerStealthMetaAddress(1, bytes("too short"));
    }

    function test_unregisteredReturnsEmpty() public view {
        bytes memory retrieved = registry.stealthMetaAddressOf(alice, 1);
        assertEq(retrieved.length, 0);
    }

    function test_differentSchemesIndependent() public {
        vm.startPrank(alice);
        registry.registerStealthMetaAddress(1, validMetaAddress);
        // Scheme 2 has no length restriction
        registry.registerStealthMetaAddress(2, bytes("arbitrary-scheme-2-data"));
        vm.stopPrank();

        assertEq(keccak256(registry.stealthMetaAddressOf(alice, 1)), keccak256(validMetaAddress));
        assertEq(
            keccak256(registry.stealthMetaAddressOf(alice, 2)),
            keccak256(bytes("arbitrary-scheme-2-data"))
        );
    }

    // ========== M-1: Two-step ownership transfer tests ==========

    function test_transferOwnership_twoStep() public {
        address newOwner = makeAddr("newOwner");

        // Step 1: Current owner initiates transfer
        vm.prank(deployer);
        registry.transferOwnership(newOwner);

        // Owner should NOT have changed yet
        assertEq(registry.owner(), deployer);
        assertEq(registry.pendingOwner(), newOwner);

        // Step 2: New owner accepts
        vm.prank(newOwner);
        registry.acceptOwnership();

        assertEq(registry.owner(), newOwner);
        assertEq(registry.pendingOwner(), address(0));
    }

    function test_transferOwnership_emitsStartedEvent() public {
        address newOwner = makeAddr("newOwner");

        vm.expectEmit(true, true, false, true);
        emit IStealthRegistry.OwnershipTransferStarted(deployer, newOwner);

        vm.prank(deployer);
        registry.transferOwnership(newOwner);
    }

    function test_acceptOwnership_emitsTransferredEvent() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(deployer);
        registry.transferOwnership(newOwner);

        vm.expectEmit(true, true, false, true);
        emit IStealthRegistry.OwnershipTransferred(deployer, newOwner);

        vm.prank(newOwner);
        registry.acceptOwnership();
    }

    function test_revert_acceptOwnership_notPending() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(deployer);
        registry.transferOwnership(newOwner);

        // Random address tries to accept
        vm.prank(alice);
        vm.expectRevert("StealthRegistry: not pending owner");
        registry.acceptOwnership();
    }

    function test_revert_acceptOwnership_noPending() public {
        vm.prank(alice);
        vm.expectRevert("StealthRegistry: not pending owner");
        registry.acceptOwnership();
    }

    function test_transferOwnership_revert_zeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert("StealthRegistry: zero owner");
        registry.transferOwnership(address(0));
    }

    function test_transferOwnership_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert("StealthRegistry: not owner");
        registry.transferOwnership(alice);
    }

    function test_constructor_emitsOwnershipTransferred() public {
        vm.expectEmit(true, true, false, true);
        emit IStealthRegistry.OwnershipTransferred(address(0), address(this));

        new StealthRegistry();
    }

    function test_transferOwnership_overwritePending() public {
        address newOwner1 = makeAddr("newOwner1");
        address newOwner2 = makeAddr("newOwner2");

        vm.prank(deployer);
        registry.transferOwnership(newOwner1);

        // Owner changes their mind
        vm.prank(deployer);
        registry.transferOwnership(newOwner2);

        assertEq(registry.pendingOwner(), newOwner2);

        // First candidate can no longer accept
        vm.prank(newOwner1);
        vm.expectRevert("StealthRegistry: not pending owner");
        registry.acceptOwnership();

        // Second candidate can
        vm.prank(newOwner2);
        registry.acceptOwnership();
        assertEq(registry.owner(), newOwner2);
    }
}
