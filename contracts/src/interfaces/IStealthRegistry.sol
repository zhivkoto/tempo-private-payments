// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IStealthRegistry
/// @notice Singleton registry for stealth meta-addresses (ERC-6538 adapted for Tempo).
/// @dev Users register their stealth meta-address for a given scheme ID.
///      A stealth meta-address encodes both the spending public key and viewing public key.
///      Format: abi.encodePacked(spendingPubKey, viewingPubKey) — each 33 bytes (compressed secp256k1).
interface IStealthRegistry {
    /// @notice Emitted when a user registers or updates their stealth meta-address.
    /// @param registrant The address that registered.
    /// @param schemeId The stealth scheme identifier (1 = secp256k1 ECDH).
    /// @param stealthMetaAddress The encoded stealth meta-address (66 bytes for scheme 1).
    event StealthMetaAddressSet(
        address indexed registrant,
        uint256 indexed schemeId,
        bytes stealthMetaAddress
    );

    /// @notice Register or update your stealth meta-address for a given scheme.
    /// @param schemeId The scheme identifier. Must be > 0.
    /// @param stealthMetaAddress The stealth meta-address bytes.
    ///        For scheme 1: abi.encodePacked(spendingPubKey, viewingPubKey) = 66 bytes.
    function registerStealthMetaAddress(
        uint256 schemeId,
        bytes calldata stealthMetaAddress
    ) external;

    /// @notice Look up a registered stealth meta-address.
    /// @param registrant The address to look up.
    /// @param schemeId The scheme identifier.
    /// @return The stealth meta-address bytes. Empty if not registered.
    function stealthMetaAddressOf(
        address registrant,
        uint256 schemeId
    ) external view returns (bytes memory);
}
