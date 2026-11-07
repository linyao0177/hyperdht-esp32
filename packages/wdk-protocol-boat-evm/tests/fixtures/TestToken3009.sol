// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// A minimal EIP-3009 token for local tests: open mint, transferWithAuthorization
// under the domain given at deployment. Not for any real chain.
contract TestToken3009 {
    string public name;
    string public version;
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;
    bytes32 public immutable DOMAIN_SEPARATOR;

    bytes32 constant TRANSFER_TYPEHASH = keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    event Transfer(address indexed from, address indexed to, uint256 value);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    constructor(string memory name_, string memory version_) {
        name = name_;
        version = version_;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name_)), keccak256(bytes(version_)), block.chainid, address(this)));
    }

    function mint(address to, uint256 value) external {
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }

    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp > validAfter, "authorization is not yet valid");
        require(block.timestamp < validBefore, "authorization is expired");
        require(!authorizationState[from][nonce], "authorization is used");
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(TRANSFER_TYPEHASH, from, to, value, validAfter, validBefore, nonce))));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == from, "invalid signature");
        authorizationState[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);
        require(balanceOf[from] >= value, "transfer amount exceeds balance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}
