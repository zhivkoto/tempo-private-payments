// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IStealthAnnouncer} from "./interfaces/IStealthAnnouncer.sol";

/// @title StealthAnnouncer
/// @notice Singleton announcer for stealth payments on Tempo.
/// @dev Adapted from ERC-5564 for TIP-20.
///      Charges a configurable TIP-20 fee per announcement to prevent DoS.
///      Fee is collected via TIP-20 transferFrom (caller must approve this contract first).
///
///      TIP-20 interaction: On Tempo, TIP-20 tokens are system precompiles, not Solidity
///      ERC-20 contracts. However, they expose the same transferFrom(address,address,uint256)
///      interface callable via a standard low-level call to the token's precompile address.
contract StealthAnnouncer is IStealthAnnouncer {
    address public owner;
    uint256 public override announcementFee;
    address public override feeToken;
    address public override treasury;

    modifier onlyOwner() {
        require(msg.sender == owner, "StealthAnnouncer: not owner");
        _;
    }

    /// @param _feeToken The TIP-20 token address used for fees.
    /// @param _announcementFee Initial fee amount in base units.
    /// @param _treasury Address that receives collected fees.
    constructor(address _feeToken, uint256 _announcementFee, address _treasury) {
        require(_feeToken != address(0), "StealthAnnouncer: zero fee token");
        require(_treasury != address(0), "StealthAnnouncer: zero treasury");
        owner = msg.sender;
        feeToken = _feeToken;
        announcementFee = _announcementFee;
        treasury = _treasury;
    }

    /// @inheritdoc IStealthAnnouncer
    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        uint8 viewTag,
        bytes calldata metadata
    ) external {
        require(stealthAddress != address(0), "StealthAnnouncer: zero stealth address");
        require(ephemeralPubKey.length == 33, "StealthAnnouncer: invalid ephemeral pubkey length");

        // Collect fee via TIP-20 transferFrom
        if (announcementFee > 0) {
            (bool success, bytes memory returnData) = feeToken.call(
                abi.encodeWithSignature(
                    "transferFrom(address,address,uint256)",
                    msg.sender,
                    treasury,
                    announcementFee
                )
            );
            require(
                success && (returnData.length == 0 || abi.decode(returnData, (bool))),
                "StealthAnnouncer: fee transfer failed"
            );
        }

        emit Announcement(schemeId, stealthAddress, msg.sender, ephemeralPubKey, viewTag, metadata);
    }

    /// @inheritdoc IStealthAnnouncer
    function setAnnouncementFee(uint256 newFee) external onlyOwner {
        announcementFee = newFee;
    }

    /// @inheritdoc IStealthAnnouncer
    function setTreasury(address newTreasury) external onlyOwner {
        require(newTreasury != address(0), "StealthAnnouncer: zero treasury");
        treasury = newTreasury;
    }

    /// @notice Transfer ownership.
    /// @param newOwner The new owner address.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "StealthAnnouncer: zero owner");
        owner = newOwner;
    }
}
