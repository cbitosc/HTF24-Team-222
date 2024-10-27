// SPDX-License-Identifier: CC0
pragma solidity ^0.8.0;


contract Message {
    string public myMessage;

    constructor(string memory initialMessage) {
        myMessage = initialMessage;
    }

    function setMessage(string memory x) public {
        myMessage = x;
    }

    function getMessage() public view returns (string memory) {
        return myMessage;
    }
}