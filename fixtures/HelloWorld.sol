// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract HelloWorld {
    string private message;

    constructor() {
        message = "hello";
    }

    function setMessage(string calldata newMessage) external {
        message = newMessage;
    }

    function getMessage() external view returns (string memory) {
        return message;
    }
}
