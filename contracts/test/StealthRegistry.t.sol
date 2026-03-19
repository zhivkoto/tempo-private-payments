// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/StealthRegistry.sol";
import "../src/interfaces/IStealthRegistry.sol";

contract StealthRegistryTest is Test {
    StealthRegistry public registry;
    address public alice = makeAddr("alice");

    // Valid scheme 1 meta-address: two compressed secp256k1 pubkeys (33 + 33 = 66 bytes)
    bytes public validMetaAddress = abi.encodePacked(
        // spending pubkey (33 bytes, starts with 0x02)
        bytes1(0x02), bytes32(0x0000000000000000000000000000000000000000000000000000000000000001),
        // viewing pubkey (33 bytes, starts with 0x03)
        bytes1(0x03), bytes32(0x0000000000000000000000000000000000000000000000000000000000000002)
    );

    function setUp() public {
        registry = new StealthRegistry();
    }

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
}
