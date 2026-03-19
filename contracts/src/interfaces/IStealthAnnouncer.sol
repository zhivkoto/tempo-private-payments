// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IStealthAnnouncer
/// @notice Singleton announcer for stealth address payments (ERC-5564 adapted for Tempo).
/// @dev Emits Announcement events so recipients can scan for payments addressed to them.
///      Charges a small TIP-20 fee per announcement to prevent DoS spam.
interface IStealthAnnouncer {
    /// @notice Emitted for each stealth payment announcement.
    /// @param schemeId The stealth scheme identifier (indexed for filtering).
    /// @param stealthAddress The one-time stealth address that received payment (indexed).
    /// @param caller The address that called announce() (indexed). Note: this is the
    ///        payer in the default client-pays flow.
    /// @param ephemeralPubKey The ephemeral public key used in ECDH derivation (33 bytes compressed).
    /// @param viewTag Single byte for fast filtering (eliminates 255/256 of irrelevant events).
    /// @param metadata Arbitrary metadata (e.g., payment reference, token address, amount).
    event Announcement(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        uint8 viewTag,
        bytes metadata
    );

    /// @notice Announce a stealth payment. Caller must have approved the fee amount
    ///         to this contract's address via TIP-20 before calling.
    /// @param schemeId The stealth scheme identifier.
    /// @param stealthAddress The derived one-time stealth address.
    /// @param ephemeralPubKey The ephemeral public key (33 bytes compressed secp256k1).
    /// @param viewTag The view tag byte.
    /// @param metadata Arbitrary metadata bytes.
    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        uint8 viewTag,
        bytes calldata metadata
    ) external;

    /// @notice Get the current announcement fee amount (in TIP-20 base units).
    /// @return The fee amount.
    function announcementFee() external view returns (uint256);

    /// @notice Get the TIP-20 token address used for fees.
    /// @return The token address.
    function feeToken() external view returns (address);

    /// @notice Get the treasury address that receives fees.
    /// @return The treasury address.
    function treasury() external view returns (address);

    /// @notice Owner-only: update the announcement fee.
    /// @param newFee The new fee amount.
    function setAnnouncementFee(uint256 newFee) external;

    /// @notice Owner-only: update the treasury address.
    /// @param newTreasury The new treasury address.
    function setTreasury(address newTreasury) external;
}
