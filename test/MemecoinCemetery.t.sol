// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {MemecoinCemetery} from "src/MemecoinCemetery.sol";

// The assignment checkout has no forge-std. Keep the submitted tests offline and
// self-contained; these are the Foundry cheatcodes used by this file only.
interface CemeteryVm {
    function warp(uint256 timestamp) external;
    function getBlockTimestamp() external view returns (uint256);
    function prank(address sender) external;
    function deal(address account, uint256 balance) external;
    function etch(address account, bytes calldata code) external;
    function cool(address target) external;
    function expectRevert(bytes calldata reason) external;
    function expectEmit(bool topic1, bool topic2, bool topic3, bool data, address emitter) external;
}

contract CemeteryToken {
    uint256 public totalSupply;
    uint256 public decimals;
    string public symbol;
    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply, uint256 places, string memory ticker) {
        totalSupply = supply;
        decimals = places;
        symbol = ticker;
    }

    function setBalance(address account, uint256 amount) external {
        balanceOf[account] = amount;
    }

    function setSupply(uint256 supply) external {
        totalSupply = supply;
    }
}

// Reflection-style balances derive their rate by walking excluded accounts.
// The excluded accounts hold zero tokens, so the holder owns the entire supply.
contract CemeteryReflectionToken {
    uint256 public totalSupply = 1_000_000e18;
    uint8 public constant decimals = 18;
    uint256 private reflectedSupply;
    mapping(address => uint256) private reflectedBalances;
    mapping(address => uint256) private excludedBalances;
    address[] private excluded;

    constructor(address holder) {
        reflectedSupply = totalSupply * 1e9;
        reflectedBalances[holder] = reflectedSupply;
        for (uint160 i = 1; i <= 10; ++i) {
            excluded.push(address(i));
        }
    }

    function balanceOf(address account) external view returns (uint256) {
        uint256 reflected = reflectedSupply;
        uint256 supply = totalSupply;
        for (uint256 i; i < excluded.length; ++i) {
            address excludedAccount = excluded[i];
            reflected -= reflectedBalances[excludedAccount];
            supply -= excludedBalances[excludedAccount];
        }
        return reflectedBalances[account] / (reflected / supply);
    }
}

contract CemeteryNoSymbolToken {
    function totalSupply() external pure returns (uint256) {
        return 1_000_000e18;
    }

    function decimals() external pure returns (uint8) {
        return 18;
    }

    function balanceOf(address) external pure returns (uint256) {
        return 1e18;
    }
}

contract CemeteryRevertingToken {
    fallback() external {
        revert("unreadable token");
    }
}

// Return exact, adversarial ABI bytes for each selector, including responses that
// a Solidity interface cannot produce. All modes are exercised through real calls.
contract CemeteryProbeToken {
    enum Mode {
        Reply,
        Revert,
        ExhaustGas,
        WriteStorage,
        ReturnBomb
    }

    struct Response {
        bytes data;
        Mode mode;
    }
    mapping(bytes4 => Response) private responses;
    uint256 private writes;

    function configure(bytes4 selector, bytes memory data, Mode mode) external {
        responses[selector] = Response(data, mode);
    }

    function setBalance(address, uint256 amount) external {
        responses[0x70a08231] = Response(abi.encode(amount), Mode.Reply);
    }

    fallback() external {
        Response storage response = responses[msg.sig];
        Mode mode = response.mode;
        if (mode == Mode.Revert) revert("token read reverted");
        if (mode == Mode.ExhaustGas) {
            assembly { for {} 1 {} {} }
        }
        if (mode == Mode.WriteStorage) ++writes;
        if (mode == Mode.ReturnBomb) {
            assembly { return(0, 65536) }
        }
        bytes memory data = response.data;
        assembly { return(add(data, 32), mload(data)) }
    }
}

abstract contract CemeteryTestTools {
    CemeteryVm internal constant vm = CemeteryVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant PERIOD = 30 days;
    bytes4 internal constant SUPPLY = 0x18160ddd;
    bytes4 internal constant BALANCE = 0x70a08231;
    bytes4 internal constant DECIMALS = 0x313ce567;
    bytes4 internal constant SYMBOL = 0x95d89b41;
    address internal constant DIGGER = address(0xD166E2);
    address internal constant HOLDER = address(0xBEEF);
    address internal constant STRANGER = address(0xBAD);

    function _grave(MemecoinCemetery cemetery, address token) internal view returns (MemecoinCemetery.Grave memory g) {
        (bool ok, bytes memory data) = address(cemetery).staticcall(abi.encodeCall(cemetery.graveOf, (token)));
        require(ok, "graveOf reverted");
        // graveOf returns a tuple. Prefix its dynamic-struct offset to decode it
        // without nine simultaneous stack locals (also works without via-IR).
        g = abi.decode(bytes.concat(abi.encode(uint256(32)), data), (MemecoinCemetery.Grave));
    }

    function _eq(uint256 actual, uint256 expected, string memory message) internal pure {
        require(actual == expected, message);
    }

    function _eq(address actual, address expected, string memory message) internal pure {
        require(actual == expected, message);
    }

    function _eq(string memory actual, string memory expected, string memory message) internal pure {
        require(keccak256(bytes(actual)) == keccak256(bytes(expected)), message);
    }

    function _sameBurial(MemecoinCemetery.Burial memory actual, MemecoinCemetery.Burial memory expected) internal pure {
        require(keccak256(abi.encode(actual)) == keccak256(abi.encode(expected)), "sealed burial was changed");
    }

    function _find(bytes memory haystack, bytes memory needle, uint256 start) internal pure returns (uint256) {
        if (needle.length > haystack.length) return type(uint256).max;
        for (uint256 i = start; i <= haystack.length - needle.length; ++i) {
            bool found = true;
            for (uint256 j; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return type(uint256).max;
    }

    function _contains(string memory text, string memory part) internal pure returns (bool) {
        return _find(bytes(text), bytes(part), 0) != type(uint256).max;
    }

    // Inspect the complete contents of an untrusted text node, so an injected
    // closing tag cannot satisfy an assertion merely by containing an escaped copy.
    function _textAt(string memory svg, string memory marker) internal pure returns (string memory) {
        bytes memory data = bytes(svg);
        uint256 start = _find(data, bytes(marker), 0);
        require(start != type(uint256).max, "missing SVG text node");
        while (start < data.length && data[start] != ">") ++start;
        ++start;
        uint256 end = start;
        while (end < data.length && data[end] != "<") ++end;
        require(end < data.length, "unterminated SVG text node");
        bytes memory result = new bytes(end - start);
        for (uint256 i; i < result.length; ++i) {
            result[i] = data[start + i];
        }
        return string(result);
    }

    function _assertSvgEnvelope(string memory svg, uint256 textNodes) internal pure {
        bytes memory data = bytes(svg);
        require(_find(data, bytes('<svg xmlns="http://www.w3.org/2000/svg"'), 0) == 0, "missing SVG root");
        require(_find(data, bytes("</g></svg>"), 0) == data.length - 10, "missing SVG end");
        uint256 opening;
        uint256 closing;
        for (uint256 i; i < data.length; ++i) {
            require(uint8(data[i]) >= 32 && uint8(data[i]) <= 126, "nonprintable SVG byte");
            if (i + 6 <= data.length) {
                if (
                    data[i] == "<" && data[i + 1] == "t" && data[i + 2] == "e" && data[i + 3] == "x"
                        && data[i + 4] == "t" && data[i + 5] == " "
                ) ++opening;
                if (
                    data[i] == "<" && data[i + 1] == "/" && data[i + 2] == "t" && data[i + 3] == "e"
                        && data[i + 4] == "x" && data[i + 5] == "t"
                ) ++closing;
            }
        }
        _eq(opening, textNodes, "injected or missing text elements");
        _eq(closing, textNodes, "unbalanced text elements");
        require(!_contains(svg, "<script"), "script injection");
    }

    function _escapedByte(bytes1 character) internal pure returns (string memory) {
        if (character == "&") return "&amp;";
        if (character == "<") return "&lt;";
        if (character == ">") return "&gt;";
        if (character == '"') return "&quot;";
        if (character == "'") return "&apos;";
        if (uint8(character) < 32 || uint8(character) > 126) return "?";
        return string(abi.encodePacked(character));
    }
}

contract MemecoinCemeteryTest is CemeteryTestTools {
    MemecoinCemetery internal cemetery;
    CemeteryToken internal token;

    event WakeOpened(address indexed token, address indexed digger, string epitaph, uint256 endsAt);
    event Resurrected(address indexed token, address indexed holder);
    event Buried(address indexed token, string epitaph, address indexed digger, uint256 sealedAt);
    event Rose(address indexed token, address indexed holder);

    function setUp() public {
        vm.warp(1_706_572_800); // 2024-01-30 UTC: 30 days later is leap day.
        cemetery = new MemecoinCemetery();
        token = new CemeteryToken(1_000_000e18, 18, "DEAD");
        token.setBalance(HOLDER, 1e18);
    }

    function _dig(address target, string memory epitaph) internal {
        vm.prank(DIGGER);
        cemetery.dig(target, epitaph);
    }

    function _bury(address target) internal {
        _dig(target, "Gone, but still in my wallet.");
        vm.warp(_grave(cemetery, target).wakeEndsAt);
        vm.prank(STRANGER);
        cemetery.seal(target);
    }

    function _probe() internal returns (CemeteryProbeToken probe) {
        probe = new CemeteryProbeToken();
        probe.configure(SUPPLY, abi.encode(uint256(1_000_000e18)), CemeteryProbeToken.Mode.Reply);
        probe.configure(DECIMALS, abi.encode(uint256(18)), CemeteryProbeToken.Mode.Reply);
        probe.configure(SYMBOL, abi.encode("PROBE"), CemeteryProbeToken.Mode.Reply);
        probe.setBalance(HOLDER, 1e18);
    }

    function _callMustRevert(address target, bytes memory input, bytes memory reason) internal {
        bytes32 beforeGrave = keccak256(abi.encode(_grave(cemetery, target)));
        uint256 beforeCount = cemetery.graveCount();
        (bool success, bytes memory actual) = address(cemetery).call{gas: 500_000}(input);
        require(!success, "expected cemetery call to revert");
        require(keccak256(actual) == keccak256(reason), "wrong custom error or unbounded external read");
        require(keccak256(abi.encode(_grave(cemetery, target))) == beforeGrave, "revert changed grave");
        _eq(cemetery.graveCount(), beforeCount, "revert changed grave count");
    }

    function test_NeverDugHasNoRecordAndNoHeadstone() public {
        MemecoinCemetery.Grave memory g = _grave(cemetery, address(token));
        require(g.state == MemecoinCemetery.State.None, "wrong initial state");
        _eq(g.digger, address(0), "unexpected digger");
        _eq(g.epitaph, "", "unexpected epitaph");
        _eq(g.dugAt + g.wakeEndsAt + g.sealedAt + g.burials + g.rises + g.saves, 0, "nonzero initial history");
        _eq(cemetery.graveCount(), 0, "nonzero initial count");
        vm.expectRevert(abi.encodeWithSelector(MemecoinCemetery.NeverDug.selector, address(token)));
        cemetery.headstone(address(token));
        _unknownBurial(address(token), 0);
        _unknownBurial(address(token), 1);
    }

    function _unknownBurial(address target, uint256 number) internal {
        vm.expectRevert(abi.encodeWithSelector(MemecoinCemetery.UnknownBurial.selector, target, number));
        cemetery.burialOf(target, number);
    }

    function test_DigIsPermissionlessAndEmitsCompleteWake() public {
        uint256 now_ = vm.getBlockTimestamp();
        vm.expectEmit(true, true, false, true, address(cemetery));
        emit WakeOpened(address(token), DIGGER, "Exit liquidity, at last.", now_ + PERIOD);
        _dig(address(token), "Exit liquidity, at last.");
        MemecoinCemetery.Grave memory g = _grave(cemetery, address(token));
        require(g.state == MemecoinCemetery.State.Wake, "wake not opened");
        _eq(g.digger, DIGGER, "wrong digger");
        _eq(g.epitaph, "Exit liquidity, at last.", "epitaph changed");
        _eq(g.dugAt, now_, "wrong dig timestamp");
        _eq(g.wakeEndsAt, now_ + PERIOD, "wrong wake duration");
        _eq(g.sealedAt + g.burials + g.rises + g.saves, 0, "premature burial history");
        _eq(cemetery.graveCount(), 0, "wake counted as grave");
    }

    function test_EpitaphLengthsZeroOne140And141() public {
        _callMustRevert(
            address(token),
            abi.encodeCall(cemetery.dig, (address(token), "")),
            abi.encodeWithSelector(MemecoinCemetery.InvalidEpitaphLength.selector, 0)
        );
        _callMustRevert(
            address(token),
            abi.encodeCall(cemetery.dig, (address(token), string(new bytes(141)))),
            abi.encodeWithSelector(MemecoinCemetery.InvalidEpitaphLength.selector, 141)
        );
        _dig(address(token), "x");
        CemeteryToken other = new CemeteryToken(1, 18, "TINY");
        string memory longest = string(new bytes(140));
        _dig(address(other), longest);
        _eq(_grave(cemetery, address(other)).epitaph, longest, "140 byte epitaph was altered");
    }

    function test_EpitaphLimitCountsBytesNotUnicodeCharacters() public {
        bytes memory text = new bytes(140);
        for (uint256 i; i < 140; i += 2) {
            text[i] = 0xc3;
            text[i + 1] = 0xa9;
        }
        _callMustRevert(
            address(token),
            abi.encodeCall(cemetery.dig, (address(token), string(bytes.concat(text, hex"c3a9")))),
            abi.encodeWithSelector(MemecoinCemetery.InvalidEpitaphLength.selector, 142)
        );
        _dig(address(token), string(text));
        _eq(bytes(_grave(cemetery, address(token)).epitaph).length, 140, "byte limit mismatch");
    }

    function test_DigRejectsEOAZeroAddressZeroSupplyAndRevertingToken() public {
        address[4] memory invalid =
            [address(0), STRANGER, address(new CemeteryToken(0, 18, "ZERO")), address(new CemeteryRevertingToken())];
        for (uint256 i; i < invalid.length; ++i) {
            _callMustRevert(
                invalid[i],
                abi.encodeCall(cemetery.dig, (invalid[i], "RIP")),
                abi.encodeWithSelector(MemecoinCemetery.InvalidToken.selector, invalid[i])
            );
        }
    }

    function test_DigRejectsMalformedSupplyResponses() public {
        CemeteryProbeToken probe = _probe();
        uint256[5] memory lengths = [uint256(0), 1, 31, 33, 64];
        for (uint256 i; i < lengths.length; ++i) {
            bytes memory malformed = new bytes(lengths[i]);
            if (malformed.length != 0) malformed[malformed.length - 1] = 0x01;
            probe.configure(SUPPLY, malformed, CemeteryProbeToken.Mode.Reply);
            _callMustRevert(
                address(probe),
                abi.encodeCall(cemetery.dig, (address(probe), "RIP")),
                abi.encodeWithSelector(MemecoinCemetery.InvalidToken.selector, address(probe))
            );
        }
    }

    function test_DigCapsSupplyGasAndRejectsStateWritesAndReturnBombs() public {
        CemeteryProbeToken probe = _probe();
        for (uint256 i = 1; i <= uint256(CemeteryProbeToken.Mode.ReturnBomb); ++i) {
            probe.configure(SUPPLY, abi.encode(uint256(1)), CemeteryProbeToken.Mode(i));
            _callMustRevert(
                address(probe),
                abi.encodeCall(cemetery.dig, (address(probe), "RIP")),
                abi.encodeWithSelector(MemecoinCemetery.InvalidToken.selector, address(probe))
            );
        }
    }

    function test_AllForbiddenStateTransitionsRevertWithoutMutation() public {
        for (uint256 i; i < 5; ++i) {
            CemeteryToken target = new CemeteryToken(1_000_000e18, 18, "STATE");
            target.setBalance(HOLDER, 1e18);
            MemecoinCemetery.State state = MemecoinCemetery.State(i);
            if (state != MemecoinCemetery.State.None) _dig(address(target), "RIP");
            if (state == MemecoinCemetery.State.Buried || state == MemecoinCemetery.State.Risen) {
                vm.warp(_grave(cemetery, address(target)).wakeEndsAt);
                cemetery.seal(address(target));
            }
            if (state == MemecoinCemetery.State.Saved) {
                vm.prank(HOLDER);
                cemetery.itLives(address(target));
            }
            if (state == MemecoinCemetery.State.Risen) {
                vm.prank(HOLDER);
                cemetery.rise(address(target));
            }
            bytes memory reason = abi.encodeWithSelector(MemecoinCemetery.InvalidState.selector, address(target), state);
            if (state == MemecoinCemetery.State.Wake || state == MemecoinCemetery.State.Buried) {
                _callMustRevert(address(target), abi.encodeCall(cemetery.dig, (address(target), "again")), reason);
            }
            if (state != MemecoinCemetery.State.Wake) {
                _callMustRevert(address(target), abi.encodeCall(cemetery.itLives, (address(target))), reason);
                _callMustRevert(address(target), abi.encodeCall(cemetery.seal, (address(target))), reason);
            }
            if (state != MemecoinCemetery.State.Buried) {
                _callMustRevert(address(target), abi.encodeCall(cemetery.rise, (address(target))), reason);
            }
        }
    }

    function test_SealRejectsOneSecondEarlyAndSucceedsAtDeadline() public {
        _dig(address(token), "RIP");
        MemecoinCemetery.Grave memory opened = _grave(cemetery, address(token));
        vm.warp(opened.wakeEndsAt - 1);
        _callMustRevert(
            address(token),
            abi.encodeCall(cemetery.seal, (address(token))),
            abi.encodeWithSelector(MemecoinCemetery.WakeStillOpen.selector, opened.wakeEndsAt)
        );
        vm.warp(opened.wakeEndsAt);
        vm.expectEmit(true, true, false, true, address(cemetery));
        emit Buried(address(token), "RIP", DIGGER, opened.wakeEndsAt);
        vm.prank(STRANGER);
        cemetery.seal(address(token));
        MemecoinCemetery.Grave memory buried = _grave(cemetery, address(token));
        require(buried.state == MemecoinCemetery.State.Buried, "not buried");
        _eq(buried.sealedAt, opened.wakeEndsAt, "wrong seal time");
        _eq(buried.burials, 1, "missing burial counter");
        _eq(cemetery.graveCount(), 1, "missing grave count");
        _sameBurial(
            cemetery.burialOf(address(token), 1),
            MemecoinCemetery.Burial(DIGGER, "RIP", opened.dugAt, opened.wakeEndsAt)
        );
        _unknownBurial(address(token), 0);
        _unknownBurial(address(token), 2);
        _unknownBurial(address(token), type(uint256).max);
    }

    function test_LateSealUsesActualTimestampAndNeedsNoWorkingTokenReads() public {
        CemeteryProbeToken probe = _probe();
        _dig(address(probe), "RIP");
        uint256 sealedAt = _grave(cemetery, address(probe)).wakeEndsAt + 365 days;
        probe.configure(SUPPLY, "", CemeteryProbeToken.Mode.Revert);
        probe.configure(BALANCE, "", CemeteryProbeToken.Mode.Revert);
        vm.warp(sealedAt);
        vm.prank(STRANGER);
        cemetery.seal(address(probe));
        _eq(cemetery.burialOf(address(probe), 1).sealedAt, sealedAt, "late seal backdated");
    }

    function test_ObjectionAtDeadlineAndLaterIsTooLate() public {
        _dig(address(token), "RIP");
        uint256 deadline = _grave(cemetery, address(token)).wakeEndsAt;
        for (uint256 i; i < 2; ++i) {
            vm.warp(deadline + i * 365 days);
            vm.expectRevert(abi.encodeWithSelector(MemecoinCemetery.WakeClosed.selector, deadline));
            vm.prank(HOLDER);
            cemetery.itLives(address(token));
        }
        require(_grave(cemetery, address(token)).state == MemecoinCemetery.State.Wake, "late objection changed state");
    }

    function test_LastSecondObjectionEmitsEventAndStartsFreshCooldown() public {
        _dig(address(token), "Not yet.");
        uint256 savedAt = _grave(cemetery, address(token)).wakeEndsAt - 1;
        vm.warp(savedAt);
        vm.expectEmit(true, true, false, true, address(cemetery));
        emit Resurrected(address(token), HOLDER);
        vm.prank(HOLDER);
        cemetery.itLives(address(token));
        MemecoinCemetery.Grave memory saved = _grave(cemetery, address(token));
        require(saved.state == MemecoinCemetery.State.Saved, "objection failed");
        _eq(saved.saves, 1, "save not counted");
        _eq(saved.burials + saved.rises + saved.sealedAt + cemetery.graveCount(), 0, "save created burial");
        _assertCooldownAndReopen(address(token), savedAt + PERIOD, 0, 0, 1);
    }

    function test_RisePreservesBurialEmitsEventAndStartsFreshCooldown() public {
        _bury(address(token));
        MemecoinCemetery.Burial memory record = cemetery.burialOf(address(token), 1);
        uint256 risenAt = vm.getBlockTimestamp() + 90 days;
        vm.warp(risenAt);
        vm.expectEmit(true, true, false, true, address(cemetery));
        emit Rose(address(token), HOLDER);
        vm.prank(HOLDER);
        cemetery.rise(address(token));
        MemecoinCemetery.Grave memory risen = _grave(cemetery, address(token));
        require(risen.state == MemecoinCemetery.State.Risen, "rise failed");
        _eq(risen.rises, 1, "rise not counted");
        _eq(cemetery.graveCount(), 0, "rise left active grave");
        _eq(risen.digger, record.digger, "rise changed digger");
        _eq(risen.epitaph, record.epitaph, "rise changed epitaph");
        _eq(risen.sealedAt, record.sealedAt, "rise changed seal time");
        _sameBurial(cemetery.burialOf(address(token), 1), record);
        _assertCooldownAndReopen(address(token), risenAt + PERIOD, 1, 1, 0);
        _sameBurial(cemetery.burialOf(address(token), 1), record);
    }

    function _assertCooldownAndReopen(address target, uint256 endsAt, uint256 burials, uint256 rises, uint256 saves)
        internal
    {
        _callMustRevert(
            target,
            abi.encodeCall(cemetery.dig, (target, "Too soon")),
            abi.encodeWithSelector(MemecoinCemetery.CooldownActive.selector, endsAt)
        );
        vm.warp(endsAt - 1);
        _callMustRevert(
            target,
            abi.encodeCall(cemetery.dig, (target, "Still too soon")),
            abi.encodeWithSelector(MemecoinCemetery.CooldownActive.selector, endsAt)
        );
        vm.warp(endsAt);
        vm.prank(STRANGER);
        cemetery.dig(target, "Another chance.");
        MemecoinCemetery.Grave memory reopened = _grave(cemetery, target);
        require(reopened.state == MemecoinCemetery.State.Wake, "cooldown boundary rejected");
        _eq(reopened.digger, STRANGER, "new digger missing");
        _eq(reopened.epitaph, "Another chance.", "new epitaph missing");
        _eq(reopened.dugAt, endsAt, "new dig timestamp missing");
        _eq(reopened.wakeEndsAt, endsAt + PERIOD, "new deadline missing");
        _eq(reopened.sealedAt, 0, "old seal displayed on new wake");
        _eq(reopened.burials, burials, "burial counter reset");
        _eq(reopened.rises, rises, "rise counter reset");
        _eq(reopened.saves, saves, "save counter reset");
    }

    // Exercise both holder-only entrypoints at threshold-1 and at the exact threshold.
    function _exerciseThreshold(address target, uint256 threshold) internal {
        _dig(target, "Threshold test");
        CemeteryToken(target).setBalance(HOLDER, threshold - 1);
        vm.expectRevert(abi.encodeWithSelector(MemecoinCemetery.NotHolder.selector, target, HOLDER, threshold));
        vm.prank(HOLDER);
        cemetery.itLives(target);
        require(_grave(cemetery, target).state == MemecoinCemetery.State.Wake, "nonholder saved token");
        CemeteryToken(target).setBalance(HOLDER, threshold);
        vm.prank(HOLDER);
        cemetery.itLives(target);
        require(_grave(cemetery, target).state == MemecoinCemetery.State.Saved, "exact holder could not object");
        vm.warp(vm.getBlockTimestamp() + PERIOD);
        _bury(target);
        CemeteryToken(target).setBalance(HOLDER, threshold - 1);
        vm.expectRevert(abi.encodeWithSelector(MemecoinCemetery.NotHolder.selector, target, HOLDER, threshold));
        vm.prank(HOLDER);
        cemetery.rise(target);
        _eq(cemetery.graveCount(), 1, "failed rise changed count");
        CemeteryToken(target).setBalance(HOLDER, threshold);
        vm.prank(HOLDER);
        cemetery.rise(target);
        require(_grave(cemetery, target).state == MemecoinCemetery.State.Risen, "exact holder could not rise");
        _eq(cemetery.graveCount(), 0, "successful rise did not remove grave");
    }

    function test_HolderSmallSupplyUsesOneTenthPercent18Decimals() public {
        _exerciseThreshold(address(new CemeteryToken(100e18, 18, "SMALL")), 1e17);
    }

    function test_HolderHugeSupplyNeedsOnlyOneWhole18DecimalToken() public {
        _exerciseThreshold(address(new CemeteryToken(type(uint256).max, 18, "HUGE")), 1e18);
    }

    function test_HolderSmallSixDecimalSupplyUsesOneTenthPercent() public {
        _exerciseThreshold(address(new CemeteryToken(100e6, 6, "SMALL6")), 1e5);
    }

    function test_HolderHugeSixDecimalSupplyNeedsOnlyOneWholeToken() public {
        _exerciseThreshold(address(new CemeteryToken(100_000_000_000e6, 6, "USDC-LIKE")), 1e6);
    }

    function test_HolderTinySupplyFloorAndIntegerRounding() public {
        uint256[5] memory supplies = [uint256(1), 999, 1000, 1999, 2000];
        uint256[5] memory expected = [uint256(1), 1, 1, 1, 2];
        for (uint256 i; i < supplies.length; ++i) {
            _exerciseThreshold(address(new CemeteryToken(supplies[i], 18, "TINY")), expected[i]);
        }
    }

    function test_HolderDecimalsZero36AndAbove36() public {
        uint256[5] memory decimals_ = [uint256(0), 36, 37, 255, type(uint256).max];
        uint256[5] memory expected = [uint256(1), 1e36, 1e18, 1e18, 1e18];
        for (uint256 i; i < decimals_.length; ++i) {
            _exerciseThreshold(address(new CemeteryToken(type(uint256).max, decimals_[i], "DEC")), expected[i]);
        }
    }

    function test_UnreadableDecimalsDefaultsTo18ForBothHolderActions() public {
        for (uint256 i; i < 7; ++i) {
            CemeteryProbeToken probe = _probe();
            bytes memory response = i < 3 ? new bytes(i == 0 ? 0 : i == 1 ? 31 : 64) : abi.encode(uint256(6));
            CemeteryProbeToken.Mode mode = i < 3 ? CemeteryProbeToken.Mode.Reply : CemeteryProbeToken.Mode(i - 2);
            probe.configure(DECIMALS, response, mode);
            _exerciseThreshold(address(probe), 1e18);
        }
    }

    function test_RequiredReadFailuresDuringWakeFailClosed() public {
        _requiredReadFailures(false);
    }

    function test_RequiredReadFailuresDuringBurialFailClosed() public {
        _requiredReadFailures(true);
    }

    function _proveGasHeavyBalance(CemeteryReflectionToken target) internal {
        bytes memory input = abi.encodeCall(target.balanceOf, (HOLDER));
        vm.cool(address(target));
        (bool capped,) = address(target).staticcall{gas: 50_000}(input);
        require(!capped, "fixture must exceed the old holder-read cap");
        vm.cool(address(target));
        (bool funded, bytes memory data) = address(target).staticcall{gas: 200_000}(input);
        require(funded, "funded balance read failed");
        _eq(abi.decode(data, (uint256)), 1_000_000e18, "holder must own the entire supply");
        // Prior probes and setup must not warm storage for the cemetery's read.
        vm.cool(address(target));
    }

    function test_GasHeavyReflectionHolderCanSave() public {
        CemeteryReflectionToken target = new CemeteryReflectionToken(HOLDER);
        _dig(address(target), "Expensive does not mean dead");
        _proveGasHeavyBalance(target);
        vm.prank(HOLDER);
        cemetery.itLives{gas: 300_000}(address(target));
        MemecoinCemetery.Grave memory saved = _grave(cemetery, address(target));
        require(saved.state == MemecoinCemetery.State.Saved, "gas-heavy holder could not save");
        _eq(saved.saves, 1, "save not counted");
        _eq(cemetery.graveCount(), 0, "saved token counted as buried");
    }

    function test_GasHeavyReflectionHolderCanRise() public {
        CemeteryReflectionToken target = new CemeteryReflectionToken(HOLDER);
        _bury(address(target));
        MemecoinCemetery.Burial memory record = cemetery.burialOf(address(target), 1);
        _proveGasHeavyBalance(target);
        vm.prank(HOLDER);
        cemetery.rise{gas: 300_000}(address(target));
        MemecoinCemetery.Grave memory risen = _grave(cemetery, address(target));
        require(risen.state == MemecoinCemetery.State.Risen, "gas-heavy holder could not rise");
        _eq(risen.rises, 1, "rise not counted");
        _eq(cemetery.graveCount(), 0, "risen token counted as buried");
        _sameBurial(cemetery.burialOf(address(target), 1), record);
    }

    function _requiredReadFailures(bool buried) internal {
        CemeteryProbeToken probe = _probe();
        if (buried) _bury(address(probe));
        else _dig(address(probe), "RIP");
        bytes memory action = buried
            ? abi.encodeCall(cemetery.rise, (address(probe)))
            : abi.encodeCall(cemetery.itLives, (address(probe)));
        bytes4[2] memory selectors = [SUPPLY, BALANCE];
        for (uint256 j; j < selectors.length; ++j) {
            for (uint256 i; i < 7; ++i) {
                bytes memory response = i < 3 ? new bytes(i == 0 ? 0 : i == 1 ? 31 : 64) : abi.encode(uint256(1e18));
                CemeteryProbeToken.Mode mode = i < 3 ? CemeteryProbeToken.Mode.Reply : CemeteryProbeToken.Mode(i - 2);
                // Holder reads are caller-funded; do not require a cap for an infinite loop.
                if (mode == CemeteryProbeToken.Mode.ExhaustGas) continue;
                probe.configure(selectors[j], response, mode);
                _callMustRevert(
                    address(probe),
                    action,
                    abi.encodeWithSelector(MemecoinCemetery.TokenReadFailed.selector, address(probe), selectors[j])
                );
            }
            probe.configure(selectors[j], abi.encode(uint256(1_000_000e18)), CemeteryProbeToken.Mode.Reply);
        }
    }

    function test_HolderReadsCurrentSupplyAndBalanceNotDigTimeSnapshot() public {
        _dig(address(token), "RIP");
        token.setSupply(2000);
        token.setBalance(HOLDER, 1);
        vm.expectRevert(abi.encodeWithSelector(MemecoinCemetery.NotHolder.selector, address(token), HOLDER, 2));
        vm.prank(HOLDER);
        cemetery.itLives(address(token));
        token.setBalance(HOLDER, 2); // A transient/borrowed balance is intentionally enough.
        vm.prank(HOLDER);
        cemetery.itLives(address(token));
        token.setBalance(HOLDER, 0);
        require(
            _grave(cemetery, address(token)).state == MemecoinCemetery.State.Saved,
            "returning borrowed balance undid save"
        );
        vm.warp(vm.getBlockTimestamp() + PERIOD);
        _bury(address(token));
        token.setSupply(999);
        token.setBalance(HOLDER, 1);
        vm.prank(HOLDER);
        cemetery.rise(address(token));
        token.setBalance(HOLDER, 0);
        require(
            _grave(cemetery, address(token)).state == MemecoinCemetery.State.Risen,
            "returning borrowed balance undid rise"
        );
    }

    function test_HeadstoneEscapesAllFiveXMLCharactersInBothTextInputs() public {
        CemeteryToken special = new CemeteryToken(1000, 18, '<>&"\'');
        string memory epitaph = '</text><script>alert("x" & \'y\')</script>';
        _dig(address(special), epitaph);
        string memory svg = cemetery.headstone(address(special));
        _eq(_textAt(svg, 'y="205"'), "&lt;&gt;&amp;&quot;&apos;", "unsafe symbol escaping");
        _eq(
            _textAt(svg, 'y="310"'),
            "&lt;/text&gt;&lt;script&gt;alert(&quot;x&quot; &amp; &apos;y&apos;)&lt;/script&gt;",
            "unsafe epitaph escaping"
        );
        _eq(_grave(cemetery, address(special)).epitaph, epitaph, "stored epitaph must remain unescaped");
        _assertSvgEnvelope(svg, 5);
    }

    function test_HeadstoneRemainsValidWith140Metacharacters() public {
        bytes memory epitaph = new bytes(140);
        bytes memory alphabet = bytes("<>&");
        string memory expected;
        for (uint256 i; i < epitaph.length; ++i) {
            epitaph[i] = alphabet[i % 3];
            expected = string.concat(expected, i % 3 == 0 ? "&lt;" : i % 3 == 1 ? "&gt;" : "&amp;");
        }
        _dig(address(token), string(epitaph));
        string memory svg = cemetery.headstone(address(token));
        _eq(_textAt(svg, 'y="310"'), expected, "metacharacters escaped incorrectly");
        _assertSvgEnvelope(svg, 5);
    }

    function test_EveryByteIsEscapedOrMadePrintable() public {
        for (uint256 batch; batch < 2; ++batch) {
            bytes memory epitaph = new bytes(128);
            string memory expected;
            for (uint256 i; i < 128; ++i) {
                epitaph[i] = bytes1(uint8(batch * 128 + i));
                expected = string.concat(expected, _escapedByte(epitaph[i]));
            }
            CemeteryToken target = new CemeteryToken(1000, 18, "ASCII");
            _dig(address(target), string(epitaph));
            string memory svg = cemetery.headstone(address(target));
            _eq(_textAt(svg, 'y="310"'), expected, "byte escaping mismatch");
            _assertSvgEnvelope(svg, 5);
        }
    }

    function test_MissingSymbolUsesShortAddressAndStillAllowsHolders() public {
        CemeteryNoSymbolToken noSymbol = new CemeteryNoSymbolToken();
        address target = address(bytes20(hex"1234567890abcdef1234567890abcdef1234cdef"));
        vm.etch(target, address(noSymbol).code);
        _dig(target, "Anonymous");
        _eq(_textAt(cemetery.headstone(target), 'y="205"'), "0x1234...cdef", "missing symbol fallback");
        vm.prank(HOLDER);
        cemetery.itLives(target);
        require(_grave(cemetery, target).state == MemecoinCemetery.State.Saved, "symbol incorrectly required to object");
    }

    function test_MalformedAndNonprintableSymbolsFallBackSafely() public {
        CemeteryProbeToken implementation = _probe();
        address target = address(bytes20(hex"1234567890abcdef1234567890abcdef1234cdef"));
        vm.etch(target, address(implementation).code);
        CemeteryProbeToken probe = CemeteryProbeToken(target);
        probe.configure(SUPPLY, abi.encode(uint256(1000)), CemeteryProbeToken.Mode.Reply);
        _dig(target, "Anonymous");
        bytes[] memory malformed = new bytes[](13);
        malformed[0] = "";
        malformed[1] = abi.encode(bytes32("LEGACY"));
        malformed[2] = abi.encode(uint256(0), uint256(1), bytes32("X"));
        malformed[3] = abi.encode(uint256(64), uint256(1), bytes32("X"));
        malformed[4] = abi.encode(uint256(32), type(uint256).max);
        malformed[5] = abi.encode(uint256(32), uint256(33), bytes32("X"));
        malformed[6] = abi.encode("");
        malformed[7] = abi.encode(string(hex"410042"));
        malformed[8] = abi.encode(string(hex"411f42"));
        malformed[9] = abi.encode(string(hex"417f42"));
        malformed[10] = abi.encode(string(abi.encodePacked(hex"418042")));
        malformed[11] = abi.encode(string(abi.encodePacked(hex"41ff42")));
        malformed[12] = abi.encode(unicode"💀");
        for (uint256 i; i < malformed.length; ++i) {
            probe.configure(SYMBOL, malformed[i], CemeteryProbeToken.Mode.Reply);
            _assertFallbackSymbol(target);
        }
        for (uint256 i = 1; i <= uint256(CemeteryProbeToken.Mode.ReturnBomb); ++i) {
            probe.configure(SYMBOL, abi.encode("IGNORED"), CemeteryProbeToken.Mode(i));
            _assertFallbackSymbol(target);
        }
    }

    function _assertFallbackSymbol(address target) internal view {
        // A token that burns its read allowance must not burn the caller's budget.
        (bool ok, bytes memory data) =
            address(cemetery).staticcall{gas: 1_000_000}(abi.encodeCall(cemetery.headstone, (target)));
        require(ok, "hostile symbol prevented headstone rendering");
        _eq(_textAt(abi.decode(data, (string)), 'y="205"'), "0x1234...cdef", "unsafe symbol fallback");
    }

    function test_PrintableSymbolSpaceAndTildeAreAccepted() public {
        CemeteryToken printable = new CemeteryToken(1000, 18, " ~ASCII~ ");
        _dig(address(printable), "RIP");
        _eq(_textAt(cemetery.headstone(address(printable)), 'y="205"'), " ~ASCII~ ", "printable ASCII rejected");
    }

    function test_HeadstoneLeapDaySealDateAndUnsetDateDash() public {
        _dig(address(token), "RIP");
        string memory svg = cemetery.headstone(address(token));
        _eq(_textAt(svg, 'y="385"'), "Dug: 2024-01-30", "wrong dig date");
        _eq(_textAt(svg, 'y="420"'), "Sealed: -", "unset seal date missing dash");
        require(!_contains(svg, "RISEN"), "premature risen banner");
        vm.warp(1_709_164_800);
        cemetery.seal(address(token));
        svg = cemetery.headstone(address(token));
        _eq(_textAt(svg, 'y="420"'), "Sealed: 2024-02-29", "wrong leap-day seal date");
        require(!_contains(svg, "RISEN"), "buried token marked risen");
    }

    function test_HeadstoneUTCDateGoldenVectors() public {
        uint256[10] memory timestamps =
            [uint256(0), 86399, 86400, 946598400, 951696000, 951782400, 951868800, 1735603200, 4107456000, 4107542400];
        string[10] memory dates = [
            "1970-01-01",
            "1970-01-01",
            "1970-01-02",
            "1999-12-31",
            "2000-02-28",
            "2000-02-29",
            "2000-03-01",
            "2024-12-31",
            "2100-02-28",
            "2100-03-01"
        ];
        for (uint256 i; i < timestamps.length; ++i) {
            vm.warp(timestamps[i]);
            CemeteryToken target = new CemeteryToken(1000, 18, "DATE");
            _dig(address(target), "RIP");
            _eq(
                _textAt(cemetery.headstone(address(target)), 'y="385"'),
                string.concat("Dug: ", dates[i]),
                "UTC/Gregorian date mismatch"
            );
        }
    }

    function test_RepeatedCyclesKeepCountersArchivesAndRisenBanner() public {
        for (uint256 i = 1; i <= 12; ++i) {
            _dig(address(token), "Saved once more");
            vm.prank(HOLDER);
            cemetery.itLives(address(token));
            string memory savedSvg = cemetery.headstone(address(token));
            _eq(_textAt(savedSvg, 'y="420"'), "Sealed: -", "saved token shows stale seal");
            require(!_contains(savedSvg, "RISEN"), "saved token shows risen banner");
            vm.warp(vm.getBlockTimestamp() + PERIOD);
            _bury(address(token));
            vm.prank(HOLDER);
            cemetery.rise(address(token));
            MemecoinCemetery.Grave memory g = _grave(cemetery, address(token));
            _eq(g.burials, i, "burials reset");
            _eq(g.rises, i, "rises reset");
            _eq(g.saves, i, "saves reset");
            _eq(cemetery.graveCount(), 0, "historical graves counted as current");
            vm.warp(vm.getBlockTimestamp() + PERIOD);
        }
        string memory svg = cemetery.headstone(address(token));
        _eq(_textAt(svg, 'y="490"'), "RISEN 12", "incorrect multiple-digit rise count");
        _assertSvgEnvelope(svg, 6);
        require(
            cemetery.burialOf(address(token), 1).sealedAt < cemetery.burialOf(address(token), 12).sealedAt,
            "history overwritten"
        );
    }

    function test_ETHReceiveFallbackAndPayableFunctionCallsAreRejected() public {
        vm.deal(address(this), 2 ether);
        for (uint256 i; i < 4; ++i) {
            bytes memory input = i < 2 ? bytes("") : abi.encodePacked(hex"deadbeef");
            uint256 value = i % 2 == 0 ? 0 : 1 ether;
            (bool ok, bytes memory reason) = address(cemetery).call{value: value}(input);
            require(!ok, "receive/fallback accepted call");
            require(
                keccak256(reason) == keccak256(abi.encodeWithSelector(MemecoinCemetery.EtherNotAccepted.selector)),
                "wrong ETH rejection error"
            );
        }
        (bool accepted,) = address(cemetery).call{value: 1}(abi.encodeCall(cemetery.dig, (address(token), "RIP")));
        require(!accepted, "dig accepted ETH");
        _eq(address(cemetery).balance, 0, "cemetery retained ETH");
        require(_grave(cemetery, address(token)).state == MemecoinCemetery.State.None, "payable dig changed state");
    }

    /// forge-config: default.fuzz.runs = 1000
    function testFuzz_HolderThresholdAtBothEdges(uint256 supply, uint8 decimals_) public {
        if (supply == 0) supply = 1;
        uint256 places = uint256(decimals_) % 39;
        uint256 whole = 10 ** (places > 36 ? 18 : places);
        uint256 expected = supply / 1000;
        if (expected > whole) expected = whole;
        if (expected == 0) expected = 1;
        _exerciseThreshold(address(new CemeteryToken(supply, places, "FUZZ")), expected);
    }

    /// forge-config: default.fuzz.runs = 256
    function testFuzz_SealedRecordNeverChanges(address firstDigger, bytes memory text, uint32 delay, uint8 repetitions)
        public
    {
        if (text.length == 0) text = hex"00";
        if (text.length > 140) {
            assembly ("memory-safe") { mstore(text, 140) }
        }
        string memory epitaph = string(text);
        vm.prank(firstDigger);
        cemetery.dig(address(token), epitaph);
        uint256 dugAt = vm.getBlockTimestamp();
        vm.warp(dugAt + PERIOD + uint256(delay));
        cemetery.seal(address(token));
        MemecoinCemetery.Burial memory original =
            MemecoinCemetery.Burial(firstDigger, epitaph, dugAt, vm.getBlockTimestamp());
        _sameBurial(cemetery.burialOf(address(token), 1), original);
        uint256 count = uint256(repetitions) % 4 + 1;
        for (uint256 i; i < count; ++i) {
            vm.prank(HOLDER);
            cemetery.rise(address(token));
            _sameBurial(cemetery.burialOf(address(token), 1), original);
            vm.warp(vm.getBlockTimestamp() + PERIOD);
            _dig(address(token), "A replacement wake must not edit the archive");
            vm.prank(HOLDER);
            cemetery.itLives(address(token));
            _sameBurial(cemetery.burialOf(address(token), 1), original);
            vm.warp(vm.getBlockTimestamp() + PERIOD);
            _bury(address(token));
            _sameBurial(cemetery.burialOf(address(token), 1), original);
        }
        _eq(_grave(cemetery, address(token)).burials, count + 1, "missing subsequent burials");
    }

    /// forge-config: default.fuzz.runs = 256
    function testFuzz_EpitaphLengthAndSafeRendering(bytes memory input) public {
        // Include invalid lengths instead of discarding them with assume().
        if (input.length == 0 || input.length > 140) {
            vm.expectRevert(abi.encodeWithSelector(MemecoinCemetery.InvalidEpitaphLength.selector, input.length));
            cemetery.dig(address(token), string(input));
            return;
        }
        _dig(address(token), string(input));
        string memory expected;
        for (uint256 i; i < input.length; ++i) {
            expected = string.concat(expected, _escapedByte(input[i]));
        }
        string memory svg = cemetery.headstone(address(token));
        _eq(_textAt(svg, 'y="310"'), expected, "fuzzed epitaph broke SVG text");
        _assertSvgEnvelope(svg, 5);
    }
}

// A separate reference model drives arbitrary valid AND invalid action sequences.
// Eligibility is computed from the model, never from the implementation's state.
contract CemeteryLifecycleHandler is CemeteryTestTools {
    MemecoinCemetery public immutable cemetery;
    CemeteryToken[4] public tokens;
    uint256[4] public thresholds;
    MemecoinCemetery.Grave[4] private model;
    uint256[4] private cooldown;
    mapping(uint256 => mapping(uint256 => MemecoinCemetery.Burial)) private archives;
    uint256 public expectedCount;
    uint256 public successfulOpens;
    uint256 public successfulSaves;
    uint256 public successfulSeals;
    uint256 public successfulRises;

    constructor(MemecoinCemetery target) {
        cemetery = target;
        tokens[0] = new CemeteryToken(100e18, 18, "SMALL");
        tokens[1] = new CemeteryToken(1_000_000_000e6, 6, "LARGE6");
        tokens[2] = new CemeteryToken(999, 18, "DUST");
        tokens[3] = new CemeteryToken(1_000_000e18, 18, "WHOLE");
        thresholds = [uint256(1e17), 1e6, 1, 1e18];
    }

    function expectedGrave(uint256 index) external view returns (MemecoinCemetery.Grave memory) {
        return model[index];
    }

    function expectedBurial(uint256 index, uint256 number) external view returns (MemecoinCemetery.Burial memory) {
        return archives[index][number];
    }

    function _actor(uint256 seed) internal pure returns (address) {
        return address(uint160(0xA1100 + seed % 4));
    }

    function _attempt(bytes memory data, address actor, bool shouldSucceed) internal {
        vm.prank(actor);
        (bool success,) = address(cemetery).call(data);
        require(success == shouldSucceed, "lifecycle action disagrees with reference model");
    }

    function open(uint256 tokenSeed, uint256 actorSeed, bytes32 epitaphSeed) public {
        uint256 i = tokenSeed % tokens.length;
        MemecoinCemetery.Grave storage g = model[i];
        bool allowed = g.state == MemecoinCemetery.State.None
            || ((g.state == MemecoinCemetery.State.Saved || g.state == MemecoinCemetery.State.Risen)
                && vm.getBlockTimestamp() >= cooldown[i]);
        address actor = _actor(actorSeed);
        string memory epitaph = string(abi.encodePacked(epitaphSeed));
        _attempt(abi.encodeCall(cemetery.dig, (address(tokens[i]), epitaph)), actor, allowed);
        if (!allowed) return;
        g.state = MemecoinCemetery.State.Wake;
        g.digger = actor;
        g.epitaph = epitaph;
        g.dugAt = vm.getBlockTimestamp();
        g.wakeEndsAt = vm.getBlockTimestamp() + PERIOD;
        g.sealedAt = 0;
        ++successfulOpens;
    }

    function object(uint256 tokenSeed, uint256 actorSeed, bool holder) public {
        uint256 i = tokenSeed % tokens.length;
        MemecoinCemetery.Grave storage g = model[i];
        address actor = _actor(actorSeed);
        tokens[i].setBalance(actor, holder ? thresholds[i] : thresholds[i] - 1);
        bool allowed = g.state == MemecoinCemetery.State.Wake && vm.getBlockTimestamp() < g.wakeEndsAt && holder;
        _attempt(abi.encodeCall(cemetery.itLives, (address(tokens[i]))), actor, allowed);
        if (!allowed) return;
        g.state = MemecoinCemetery.State.Saved;
        ++g.saves;
        cooldown[i] = vm.getBlockTimestamp() + PERIOD;
        ++successfulSaves;
    }

    function seal(uint256 tokenSeed, uint256 actorSeed) public {
        uint256 i = tokenSeed % tokens.length;
        MemecoinCemetery.Grave storage g = model[i];
        bool allowed = g.state == MemecoinCemetery.State.Wake && vm.getBlockTimestamp() >= g.wakeEndsAt;
        _attempt(abi.encodeCall(cemetery.seal, (address(tokens[i]))), _actor(actorSeed), allowed);
        if (!allowed) return;
        g.state = MemecoinCemetery.State.Buried;
        g.sealedAt = vm.getBlockTimestamp();
        ++g.burials;
        archives[i][g.burials] = MemecoinCemetery.Burial(g.digger, g.epitaph, g.dugAt, g.sealedAt);
        ++expectedCount;
        ++successfulSeals;
    }

    function raise(uint256 tokenSeed, uint256 actorSeed, bool holder) public {
        uint256 i = tokenSeed % tokens.length;
        MemecoinCemetery.Grave storage g = model[i];
        address actor = _actor(actorSeed);
        tokens[i].setBalance(actor, holder ? thresholds[i] : thresholds[i] - 1);
        bool allowed = g.state == MemecoinCemetery.State.Buried && holder;
        _attempt(abi.encodeCall(cemetery.rise, (address(tokens[i]))), actor, allowed);
        if (!allowed) return;
        g.state = MemecoinCemetery.State.Risen;
        ++g.rises;
        cooldown[i] = vm.getBlockTimestamp() + PERIOD;
        --expectedCount;
        ++successfulRises;
    }

    function advance(uint256 elapsed) public {
        vm.warp(vm.getBlockTimestamp() + elapsed % (60 days + 1));
    }
}

contract MemecoinCemeteryInvariantTest is CemeteryTestTools {
    MemecoinCemetery internal cemetery;
    CemeteryLifecycleHandler internal handler;

    function setUp() public {
        vm.warp(1_706_572_800);
        cemetery = new MemecoinCemetery();
        handler = new CemeteryLifecycleHandler(cemetery);
        // Begin with one token in each non-None state and real burial history.
        // This prevents a random run from passing solely because no wake expired.
        handler.open(0, 0, bytes32("unopposed"));
        handler.open(1, 1, bytes32("buried"));
        handler.open(2, 2, bytes32("saved"));
        handler.object(2, 0, true);
        handler.open(3, 3, bytes32("zombie"));
        handler.advance(PERIOD);
        handler.seal(1, 0);
        handler.seal(3, 1);
        handler.raise(3, 2, true);
    }

    // Foundry's invariant discovery interface, without a forge-std dependency.
    function targetContracts() external view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    /// forge-config: default.invariant.runs = 128
    /// forge-config: default.invariant.depth = 64
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_GraveCountEqualsCurrentlyBuriedTokens() public view {
        uint256 actualBuried;
        for (uint256 i; i < 4; ++i) {
            if (_grave(cemetery, address(handler.tokens(i))).state == MemecoinCemetery.State.Buried) ++actualBuried;
        }
        _eq(cemetery.graveCount(), actualBuried, "count differs from current Buried states");
        _eq(cemetery.graveCount(), handler.expectedCount(), "count differs from independent model");
        _eq(address(cemetery).balance, 0, "unexpected ETH custody");
    }

    /// forge-config: default.invariant.runs = 128
    /// forge-config: default.invariant.depth = 64
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_LifecycleCountersAndEveryBurialMatchModel() public view {
        for (uint256 i; i < 4; ++i) {
            address target = address(handler.tokens(i));
            MemecoinCemetery.Grave memory expected = handler.expectedGrave(i);
            require(
                keccak256(abi.encode(_grave(cemetery, target))) == keccak256(abi.encode(expected)),
                "grave differs from independent lifecycle model"
            );
            for (uint256 number = 1; number <= expected.burials; ++number) {
                _sameBurial(cemetery.burialOf(target, number), handler.expectedBurial(i, number));
            }
        }
    }

    function test_HandlerExercisesRepeatBurialsAndAllTransitions() public {
        handler.advance(PERIOD);
        handler.open(3, 0, bytes32("second wake"));
        handler.object(3, 1, false);
        handler.object(3, 1, true);
        handler.advance(PERIOD);
        handler.open(3, 2, bytes32("third wake"));
        handler.seal(3, 0); // Too early: must fail without changing the model.
        handler.advance(PERIOD);
        handler.seal(3, 0);
        handler.raise(3, 1, false);
        handler.raise(3, 1, true);
        _eq(handler.successfulOpens(), 6, "handler did not open fresh wakes");
        _eq(handler.successfulSaves(), 2, "handler did not save");
        _eq(handler.successfulSeals(), 3, "handler did not seal again");
        _eq(handler.successfulRises(), 2, "handler did not rise again");
        invariant_GraveCountEqualsCurrentlyBuriedTokens();
        invariant_LifecycleCountersAndEveryBurialMatchModel();
    }
}
