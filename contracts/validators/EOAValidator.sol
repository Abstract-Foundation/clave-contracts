// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import {IK1Validator, IERC165} from "../interfaces/IValidator.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract EOAValidator is IK1Validator, EIP712 {
    using ECDSA for bytes32;

    bytes32 private constant SIGN_MESSAGE_TYPEHASH =
        keccak256("SignMessage(string details,bytes32 hash)");

    constructor() EIP712("zkSync", "2") {}

    function validateSignature(
        bytes32 signedTxHash,
        bytes calldata signature
    ) external view returns (address signer) {
        bytes32 structHash = keccak256(
            abi.encode(
                SIGN_MESSAGE_TYPEHASH,
                keccak256(bytes("You are signing a hash of your transaction")),
                signedTxHash
            )
        );
        bytes32 signedMessageHash = _hashTypedDataV4(structHash);
        signer = ECDSA.recover(signedMessageHash, signature);
    }

    /// @inheritdoc IERC165
    function supportsInterface(
        bytes4 interfaceId
    ) external pure override returns (bool) {
        return
            interfaceId == type(IK1Validator).interfaceId ||
            interfaceId == type(IERC165).interfaceId;
    }
}
