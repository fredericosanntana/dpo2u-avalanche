// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Common Travel Rule verdict format v1 (`dpo2u.travel-rule-verdict/1`)
/// @notice Solidity reader of the verdict the Midnight TravelRuleGate publishes (dpo2u-midnight
///         docs/VERDICT-FORMAT.md). Rebuilds the canonical JSON (keys sorted, no whitespace, absent
///         optional fields omitted) and its SHA-256 digest, the value every chain stores and
///         compares. Pinned by the shared vectors in test/fixtures/verdict-v1-crosschain.json, the
///         same file the Midnight (TypeScript) and Stellar (Soroban) implementations test against.
/// @dev Every string in the format is lowercase hex, a fixed label or `[a-z0-9-:]`, so no JSON
///      escaping is needed. A verdict mirrored here by a relayer is operator trust, not a proof:
///      this library checks the form, not that Midnight produced it.
library TravelRuleVerdictV1 {
    string internal constant FORMAT = "dpo2u.travel-rule-verdict/1";

    struct Anchor {
        uint64 height;
        bytes hash; // raw bytes, hex-encoded in the JSON
        bytes tx;
    }

    struct Sanctions {
        bytes32 listRoot;
        bytes32 providerId;
        uint64 validUntil;
    }

    struct Verdict {
        bytes32 transferId;
        bool pass; // verdict == "PASS"
        bool released;
        uint8 reasonCode;
        bytes32 policyHash;
        bytes32 originatorRoot;
        bytes32 beneficiaryRoot;
        string sourceChain; // "<chain>:<network>"
        bytes sourceContract;
        bool anchored; // block + tx present (both or neither)
        Anchor anchor;
        bool hasSanctions;
        Sanctions sanctions;
    }

    error BadVerdict();
    error BadSourceChain();
    error BadLength();

    function reasonLabel(uint8 code) internal pure returns (string memory) {
        if (code == 0) return "none";
        if (code == 1) return "missing_party_info";
        if (code == 2) return "missing_originator_document_above_threshold";
        if (code == 3) return "counterparty_vasp_not_attested";
        if (code == 4) return "sanctions_hit";
        revert BadVerdict();
    }

    /// @notice Same rules as `checkVerdict` in dpo2u-midnight. Reverts on the first violation.
    function check(Verdict memory v) internal pure {
        if (v.reasonCode > 4 || v.pass != (v.reasonCode == 0) || (v.released && !v.pass)) revert BadVerdict();
        _checkSourceChain(bytes(v.sourceChain));
        _checkVar(v.sourceContract);
        if (v.anchored) {
            _checkVar(v.anchor.hash);
            _checkVar(v.anchor.tx);
        }
    }

    function digest(Verdict memory v) internal pure returns (bytes32) {
        return sha256(canonical(v));
    }

    function canonical(Verdict memory v) internal pure returns (bytes memory) {
        check(v);
        return abi.encodePacked(_head(v), _middle(v), _tail(v));
    }

    // beneficiary_root, block, format, originator_root, policy_hash
    function _head(Verdict memory v) private pure returns (bytes memory) {
        bytes memory blk = v.anchored
            ? abi.encodePacked('{"hash":', _hex(v.anchor.hash), ',"height":', _dec(v.anchor.height), "}")
            : bytes("null");
        return abi.encodePacked(
            '{"beneficiary_root":', _hex(abi.encodePacked(v.beneficiaryRoot)),
            ',"block":', blk,
            ',"format":"', FORMAT,
            '","originator_root":', _hex(abi.encodePacked(v.originatorRoot)),
            ',"policy_hash":', _hex(abi.encodePacked(v.policyHash))
        );
    }

    // reason, released, sanctions
    function _middle(Verdict memory v) private pure returns (bytes memory) {
        bytes memory s = v.hasSanctions
            ? abi.encodePacked(
                ',"sanctions":{"list_root":', _hex(abi.encodePacked(v.sanctions.listRoot)),
                ',"provider_id":', _hex(abi.encodePacked(v.sanctions.providerId)),
                ',"valid_until":', _dec(v.sanctions.validUntil), "}"
            )
            : bytes("");
        return abi.encodePacked(
            ',"reason":{"code":', _dec(v.reasonCode), ',"label":"', reasonLabel(v.reasonCode),
            '"},"released":', v.released ? "true" : "false",
            s
        );
    }

    // source_chain, source_contract, transfer_id, tx, verdict
    function _tail(Verdict memory v) private pure returns (bytes memory) {
        return abi.encodePacked(
            ',"source_chain":"', v.sourceChain,
            '","source_contract":', _hex(v.sourceContract),
            ',"transfer_id":', _hex(abi.encodePacked(v.transferId)),
            ',"tx":', v.anchored ? _hex(v.anchor.tx) : bytes("null"),
            ',"verdict":"', v.pass ? "PASS" : "FAIL", '"}'
        );
    }

    /// Quoted lowercase hex.
    function _hex(bytes memory b) private pure returns (bytes memory out) {
        bytes16 digits = "0123456789abcdef";
        out = new bytes(2 * b.length + 2);
        out[0] = '"';
        for (uint256 i = 0; i < b.length; i++) {
            out[1 + 2 * i] = digits[uint8(b[i]) >> 4];
            out[2 + 2 * i] = digits[uint8(b[i]) & 0x0f];
        }
        out[out.length - 1] = '"';
    }

    function _dec(uint256 x) private pure returns (bytes memory) {
        if (x == 0) return "0";
        uint256 n;
        for (uint256 y = x; y != 0; y /= 10) n++;
        bytes memory out = new bytes(n);
        for (; x != 0; x /= 10) out[--n] = bytes1(uint8(48 + (x % 10)));
        return out;
    }

    function _checkVar(bytes memory b) private pure {
        if (b.length == 0 || b.length > 64) revert BadLength();
    }

    /// `^[a-z0-9-]+:[a-z0-9-]+$`, at most 64 bytes.
    function _checkSourceChain(bytes memory s) private pure {
        if (s.length < 3 || s.length > 64) revert BadSourceChain();
        uint256 colons;
        uint256 at;
        for (uint256 i = 0; i < s.length; i++) {
            bytes1 c = s[i];
            if (c == ":") {
                colons++;
                at = i;
            } else if (!((c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-")) {
                revert BadSourceChain();
            }
        }
        if (colons != 1 || at == 0 || at == s.length - 1) revert BadSourceChain();
    }
}
