// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IStealthRegistry} from "./interfaces/IStealthRegistry.sol";

/// @title StealthRegistry
/// @notice Singleton registry mapping (address, schemeId) => stealth meta-address.
/// @dev Adapted from ERC-6538 for Tempo. No access control on reads.
///      Only the registrant can set their own meta-address.
///      Ownership is used for potential future admin functions.
contract StealthRegistry is IStealthRegistry {
    address public owner;
    address public pendingOwner;

    /// @dev mapping(registrant => mapping(schemeId => stealthMetaAddress))
    mapping(address => mapping(uint256 => bytes)) private _metaAddresses;

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "StealthRegistry: not owner");
        _;
    }

    /// @inheritdoc IStealthRegistry
    function registerStealthMetaAddress(
        uint256 schemeId,
        bytes calldata stealthMetaAddress
    ) external {
        require(schemeId > 0, "StealthRegistry: invalid scheme ID");
        require(stealthMetaAddress.length > 0, "StealthRegistry: empty meta-address");

        // For scheme 1 (secp256k1), meta-address = spendingPubKey (33) + viewingPubKey (33) = 66 bytes
        if (schemeId == 1) {
            require(
                stealthMetaAddress.length == 66,
                "StealthRegistry: scheme 1 requires 66 bytes (two compressed secp256k1 pubkeys)"
            );
        }

        _metaAddresses[msg.sender][schemeId] = stealthMetaAddress;
        emit StealthMetaAddressSet(msg.sender, schemeId, stealthMetaAddress);
    }

    /// @inheritdoc IStealthRegistry
    function stealthMetaAddressOf(
        address registrant,
        uint256 schemeId
    ) external view returns (bytes memory) {
        return _metaAddresses[registrant][schemeId];
    }

    /// @inheritdoc IStealthRegistry
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "StealthRegistry: zero owner");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @inheritdoc IStealthRegistry
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "StealthRegistry: not pending owner");
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}
