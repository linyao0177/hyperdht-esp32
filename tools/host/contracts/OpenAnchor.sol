// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Permissionless Merkle-root anchoring for tools/host/anchor-node.js.
///
/// Anyone can anchor a root; the first anchor of a root is kept, with who
/// anchored it and when. A receipt's validity does not depend on who anchored
/// its root, so there is no operator role and nothing to upgrade.
/// verifyAnchor matches HashAnchor.sol, so existing verifiers work unchanged.
contract OpenAnchor {
    struct Anchor {
        uint64 timestamp;
        address anchorer;
    }

    mapping(bytes32 => Anchor) public anchors;

    event RootAnchored(bytes32 indexed merkleRoot, address indexed anchorer, uint256 timestamp);

    function anchorRoot(bytes32 merkleRoot) external {
        require(merkleRoot != bytes32(0), "OpenAnchor: empty root");
        require(anchors[merkleRoot].timestamp == 0, "OpenAnchor: already anchored");

        anchors[merkleRoot] = Anchor(uint64(block.timestamp), msg.sender);
        emit RootAnchored(merkleRoot, msg.sender, block.timestamp);
    }

    /// @return timestamp when the root was anchored, or 0
    function verifyAnchor(bytes32 merkleRoot) external view returns (uint256 timestamp) {
        return anchors[merkleRoot].timestamp;
    }
}
