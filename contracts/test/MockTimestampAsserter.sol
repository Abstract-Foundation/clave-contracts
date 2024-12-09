// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import { ITimestampAsserter } from "../interfaces/ITimestampAsserter.sol";

contract MockTimestampAsserter is ITimestampAsserter {
    function assertTimestampInRange(uint256 start, uint256 end) external view {
        
    }
}
