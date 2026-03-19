// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/StealthRegistry.sol";
import "../src/StealthAnnouncer.sol";

contract Deploy is Script {
    function run() external {
        // Configure these via environment variables
        address feeToken = vm.envAddress("FEE_TOKEN");
        uint256 announcementFee = vm.envUint("ANNOUNCEMENT_FEE");
        address treasury = vm.envAddress("TREASURY");

        vm.startBroadcast();

        StealthRegistry registry = new StealthRegistry();
        StealthAnnouncer announcer = new StealthAnnouncer(feeToken, announcementFee, treasury);

        vm.stopBroadcast();

        console.log("StealthRegistry deployed at:", address(registry));
        console.log("StealthAnnouncer deployed at:", address(announcer));
    }
}
