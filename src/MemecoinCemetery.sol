// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title Memecoin Cemetery
/// @notice An ownerless cemetery where any qualifying holder can save or raise a token.
/// @dev No fees, custody, upgrades or privileged accounts. Borrowed balances count.
/// Epitaphs are unmoderated. Every sealed burial is permanently readable through burialOf.
contract MemecoinCemetery {
    enum State {
        None,
        Wake,
        Buried,
        Saved,
        Risen
    }

    struct Grave {
        State state;
        address digger;
        string epitaph;
        uint256 dugAt;
        uint256 wakeEndsAt;
        uint256 sealedAt;
        uint256 burials;
        uint256 rises;
        uint256 saves;
    }

    /// @notice An immutable snapshot, indexed by the token's one-based burial number.
    struct Burial {
        address digger;
        string epitaph;
        uint256 dugAt;
        uint256 sealedAt;
    }

    uint256 private constant PERIOD = 30 days;
    uint256 private constant READ_GAS = 50_000;
    bytes4 private constant TOTAL_SUPPLY = 0x18160ddd;
    bytes4 private constant BALANCE_OF = 0x70a08231;
    bytes4 private constant DECIMALS = 0x313ce567;
    bytes4 private constant SYMBOL = 0x95d89b41;

    mapping(address => Grave) private graves;
    mapping(address => uint256) private cooldownEndsAt;
    mapping(address => mapping(uint256 => Burial)) private burialHistory;
    uint256 private buriedCount;

    error InvalidToken(address token);
    error InvalidEpitaphLength(uint256 length);
    error InvalidState(address token, State state);
    error CooldownActive(uint256 endsAt);
    error WakeStillOpen(uint256 endsAt);
    error WakeClosed(uint256 endsAt);
    error TokenReadFailed(address token, bytes4 selector);
    error NotHolder(address token, address account, uint256 threshold);
    error NeverDug(address token);
    error UnknownBurial(address token, uint256 number);
    error EtherNotAccepted();

    event WakeOpened(address indexed token, address indexed digger, string epitaph, uint256 endsAt);
    event Resurrected(address indexed token, address indexed holder);
    event Buried(address indexed token, string epitaph, address indexed digger, uint256 sealedAt);
    event Rose(address indexed token, address indexed holder);

    /// @notice Open a 30-day wake with an epitaph of 1 to 140 bytes.
    /// @dev Saved and Risen tokens must first complete their 30-day cooldown.
    /// A new wake replaces the current display; archived burials and counters never reset.
    /// @param token A contract with a successful, nonzero totalSupply() response.
    /// @param epitaph Permanent, unmoderated text, escaped only when rendered.
    function dig(address token, string calldata epitaph) external {
        Grave storage grave = graves[token];
        State state = grave.state;
        if (state != State.None && state != State.Saved && state != State.Risen) {
            revert InvalidState(token, state);
        }
        if (state != State.None && block.timestamp < cooldownEndsAt[token]) {
            revert CooldownActive(cooldownEndsAt[token]);
        }
        uint256 length = bytes(epitaph).length;
        if (length == 0 || length > 140) revert InvalidEpitaphLength(length);
        if (token.code.length == 0) revert InvalidToken(token);
        (bool ok, uint256 supply) = _readUint(token, abi.encodeWithSelector(TOTAL_SUPPLY), READ_GAS);
        if (!ok || supply == 0) revert InvalidToken(token);

        // All token interactions are STATICCALLs: callbacks cannot mutate cemetery state.
        grave.state = State.Wake;
        grave.digger = msg.sender;
        grave.epitaph = epitaph;
        grave.dugAt = block.timestamp;
        grave.wakeEndsAt = block.timestamp + PERIOD;
        grave.sealedAt = 0;
        emit WakeOpened(token, msg.sender, epitaph, grave.wakeEndsAt);
    }

    /// @notice Cancel an open wake as a qualifying holder and begin a 30-day cooldown.
    /// @dev Objections are accepted strictly before wakeEndsAt; balances are read now.
    /// @param token The token whose wake should be cancelled.
    function itLives(address token) external {
        Grave storage grave = graves[token];
        if (grave.state != State.Wake) revert InvalidState(token, grave.state);
        if (block.timestamp >= grave.wakeEndsAt) revert WakeClosed(grave.wakeEndsAt);
        _requireHolder(token, msg.sender);
        grave.state = State.Saved;
        ++grave.saves;
        cooldownEndsAt[token] = block.timestamp + PERIOD;
        emit Resurrected(token, msg.sender);
    }

    /// @notice Seal an unopposed wake at or after its deadline; anyone may call.
    /// @dev Each seal appends an immutable snapshot and increases the current grave count.
    /// @param token The token to bury.
    function seal(address token) external {
        Grave storage grave = graves[token];
        if (grave.state != State.Wake) revert InvalidState(token, grave.state);
        if (block.timestamp < grave.wakeEndsAt) revert WakeStillOpen(grave.wakeEndsAt);
        grave.state = State.Buried;
        grave.sealedAt = block.timestamp;
        ++grave.burials;
        burialHistory[token][grave.burials] = Burial(grave.digger, grave.epitaph, grave.dugAt, grave.sealedAt);
        ++buriedCount;
        emit Buried(token, grave.epitaph, grave.digger, grave.sealedAt);
    }

    /// @notice Raise a buried token as a qualifying holder, preserving its burial record.
    /// @dev Starts a 30-day cooldown. Exactly one current grave is removed per rise.
    /// @param token The token to raise.
    function rise(address token) external {
        Grave storage grave = graves[token];
        if (grave.state != State.Buried) revert InvalidState(token, grave.state);
        _requireHolder(token, msg.sender);
        grave.state = State.Risen;
        ++grave.rises;
        --buriedCount;
        cooldownEndsAt[token] = block.timestamp + PERIOD;
        emit Rose(token, msg.sender);
    }

    /// @notice Read the current wake or grave and all lifetime counters; None returns zeros.
    /// @param token The token to inspect.
    /// @return state Current lifecycle state.
    /// @return digger Account that opened the current wake.
    /// @return epitaph Current wake's unescaped epitaph.
    /// @return dugAt Current wake's opening timestamp.
    /// @return wakeEndsAt Current wake's deadline.
    /// @return sealedAt Current wake's seal timestamp, or zero if it has not been sealed.
    /// @return burials Lifetime number of seals.
    /// @return rises Lifetime number of rises.
    /// @return saves Lifetime number of cancelled wakes.
    function graveOf(address token)
        external
        view
        returns (
            State state,
            address digger,
            string memory epitaph,
            uint256 dugAt,
            uint256 wakeEndsAt,
            uint256 sealedAt,
            uint256 burials,
            uint256 rises,
            uint256 saves
        )
    {
        Grave storage grave = graves[token];
        return (
            grave.state,
            grave.digger,
            grave.epitaph,
            grave.dugAt,
            grave.wakeEndsAt,
            grave.sealedAt,
            grave.burials,
            grave.rises,
            grave.saves
        );
    }

    /// @notice Return the number of tokens whose current state is Buried.
    /// @return count Current graves, increased only by seal and decreased only by rise.
    function graveCount() external view returns (uint256 count) {
        return buriedCount;
    }

    /// @notice Read a permanent burial, including after later rises, saves and reburials.
    /// @param token The buried token.
    /// @param number One-based burial number, at most graveOf's lifetime burial count.
    /// @return record The snapshot, which is written once and never edited or deleted.
    function burialOf(address token, uint256 number) external view returns (Burial memory record) {
        if (number == 0 || number > graves[token].burials) revert UnknownBurial(token, number);
        return burialHistory[token][number];
    }

    /// @notice Render the current headstone as standalone SVG; reverts for undug tokens.
    /// @dev Dates are Gregorian UTC. All untrusted text is XML-escaped. Unsupported symbol
    /// responses (including empty, non-ASCII or over-32-byte strings) use a shortened address.
    /// @param token The token whose headstone should be rendered.
    /// @return svg The SVG document, including a rise count banner only in state Risen.
    function headstone(address token) external view returns (string memory svg) {
        Grave storage grave = graves[token];
        if (grave.state == State.None) revert NeverDug(token);
        string memory sealDate = grave.state == State.Buried || grave.state == State.Risen ? _date(grave.sealedAt) : "-";
        string memory symbol = _symbol(token);
        svg = string.concat(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 600">',
            '<rect width="800" height="600" fill="#101719"/>',
            '<path d="M100 550V210a300 180 0 0 1 600 0v340Z" fill="#67716d" stroke="#a4ada5" stroke-width="8"/>',
            '<g text-anchor="middle" fill="#101719" font-family="monospace">',
            '<text x="400" y="130" font-size="32">R.I.P.</text>',
            '<text x="400" y="205" font-size="28"',
            bytes(symbol).length > 30 ? ' textLength="520" lengthAdjust="spacingAndGlyphs">' : ">",
            _escape(symbol),
            "</text>",
            '<text x="400" y="310" font-size="20"',
            bytes(grave.epitaph).length > 45 ? ' textLength="540" lengthAdjust="spacingAndGlyphs">' : ">",
            _escape(grave.epitaph),
            "</text>",
            '<text x="400" y="385" font-size="20">Dug: ',
            _date(grave.dugAt),
            "</text>",
            '<text x="400" y="420" font-size="20">Sealed: ',
            sealDate,
            "</text>"
        );
        if (grave.state == State.Risen) {
            svg = string.concat(
                svg, '<text x="400" y="490" font-size="30" fill="#b7ff92">RISEN ', _decimal(grave.rises), "</text>"
            );
        }
        return string.concat(svg, "</g></svg>");
    }

    /// @notice Reject all direct ETH transfers, including zero-value calls without data.
    receive() external payable {
        revert EtherNotAccepted();
    }

    /// @notice Reject unknown selectors and all ETH sent with unrecognized calldata.
    fallback() external payable {
        revert EtherNotAccepted();
    }

    /// @dev Enforce max(1, min(10**decimals, totalSupply/1000)) using current token data.
    /// Malformed decimals, reverts and values above 36 default to 18; required reads fail closed.
    /// Callers fund required reads so expensive balance/supply calculations do not exclude holders.
    function _requireHolder(address token, address account) private view {
        (bool ok, uint256 supply) = _readUint(token, abi.encodeWithSelector(TOTAL_SUPPLY), gasleft());
        if (!ok) revert TokenReadFailed(token, TOTAL_SUPPLY);
        (bool hasDecimals, uint256 decimals) = _readUint(token, abi.encodeWithSelector(DECIMALS), READ_GAS);
        if (!hasDecimals || decimals > 36) decimals = 18;
        uint256 wholeToken = 10 ** decimals;
        uint256 threshold = supply / 1000;
        if (threshold > wholeToken) threshold = wholeToken;
        if (threshold == 0) threshold = 1;
        (bool hasBalance, uint256 balance) = _readUint(token, abi.encodeWithSelector(BALANCE_OF, account), gasleft());
        if (!hasBalance) revert TokenReadFailed(token, BALANCE_OF);
        if (balance < threshold) revert NotHolder(token, account, threshold);
    }

    /// @dev Read exactly one ABI word with the supplied gas limit and a fixed output limit.
    /// STATICCALL prevents state-changing reentrancy; bounded copying prevents return-data bombs.
    function _readUint(address token, bytes memory input, uint256 gasLimit)
        private
        view
        returns (bool ok, uint256 value)
    {
        assembly ("memory-safe") {
            ok := staticcall(gasLimit, token, add(input, 32), mload(input), 0, 32)
            ok := and(ok, eq(returndatasize(), 32))
            value := mload(0)
        }
    }

    /// @dev Validate the ABI header before allocating or copying a symbol.
    /// The gas cap bounds callee memory; the 32-byte length limit also bounds rendering work.
    function _symbol(address token) private view returns (string memory) {
        bytes memory input = abi.encodeWithSelector(SYMBOL);
        uint256 gasLimit = READ_GAS;
        bool ok;
        uint256 size;
        uint256 offset;
        uint256 length;
        assembly ("memory-safe") {
            ok := staticcall(gasLimit, token, add(input, 32), mload(input), 0, 0)
            size := returndatasize()
            if and(ok, iszero(lt(size, 64))) {
                returndatacopy(0, 0, 64)
                offset := mload(0)
                length := mload(32)
            }
        }
        if (!ok || size < 64 || offset != 32 || length == 0 || length > 32) {
            return _shortAddress(token);
        }
        // Round available data down to full ABI words, avoiding arithmetic on a hostile length.
        if (length > ((size - 64) / 32) * 32) return _shortAddress(token);
        bytes memory symbol = new bytes(length);
        assembly ("memory-safe") { returndatacopy(add(symbol, 32), 64, length) }
        for (uint256 i; i < length; ++i) {
            bytes1 character = symbol[i];
            if (uint8(character) < 32 || uint8(character) > 126) return _shortAddress(token);
        }
        return string(symbol);
    }

    /// @dev Format an address as lowercase 0x1234...abcd without any external calls.
    function _shortAddress(address token) private pure returns (string memory) {
        bytes16 hexDigits = "0123456789abcdef";
        bytes memory result = bytes("0x0000...0000");
        uint160 value = uint160(token);
        for (uint256 i; i < 4; ++i) {
            result[2 + i] = hexDigits[(value >> (156 - 4 * i)) & 15];
            result[9 + i] = hexDigits[(value >> (12 - 4 * i)) & 15];
        }
        return string(result);
    }

    /// @dev Escape all five XML metacharacters and replace every non-printable byte with '?'.
    /// The largest replacement is six bytes, so the output buffer cannot overflow.
    function _escape(string memory text) private pure returns (string memory) {
        bytes memory input = bytes(text);
        bytes memory output = new bytes(input.length * 6);
        uint256 used;
        for (uint256 i; i < input.length; ++i) {
            bytes1 character = input[i];
            bytes memory replacement;
            if (character == "&") {
                replacement = bytes("&amp;");
            } else if (character == "<") {
                replacement = bytes("&lt;");
            } else if (character == ">") {
                replacement = bytes("&gt;");
            } else if (character == '"') {
                replacement = bytes("&quot;");
            } else if (character == "'") {
                replacement = bytes("&apos;");
            } else {
                output[used++] = uint8(character) < 32 || uint8(character) > 126 ? bytes1("?") : character;
                continue;
            }
            for (uint256 j; j < replacement.length; ++j) {
                output[used++] = replacement[j];
            }
        }
        assembly ("memory-safe") { mstore(output, used) }
        return string(output);
    }

    /// @dev Convert Unix seconds to Gregorian YYYY-MM-DD UTC using 400-year eras.
    /// March-based years put leap days last; work is constant regardless of the timestamp.
    function _date(uint256 timestamp) private pure returns (string memory) {
        uint256 daysSinceMarch = timestamp / 1 days + 719468;
        uint256 era = daysSinceMarch / 146097;
        uint256 dayOfEra = daysSinceMarch % 146097;
        uint256 yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
        uint256 year = yearOfEra + era * 400;
        uint256 dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100);
        uint256 marchMonth = (5 * dayOfYear + 2) / 153;
        uint256 day = dayOfYear - (153 * marchMonth + 2) / 5 + 1;
        uint256 month = marchMonth < 10 ? marchMonth + 3 : marchMonth - 9;
        if (month <= 2) ++year;
        return string.concat(
            _decimal(year), "-", month < 10 ? "0" : "", _decimal(month), "-", day < 10 ? "0" : "", _decimal(day)
        );
    }

    /// @dev Convert an unsigned integer to printable decimal ASCII, including zero.
    function _decimal(uint256 value) private pure returns (string memory) {
        uint256 digits = 1;
        for (uint256 remaining = value; remaining >= 10; remaining /= 10) {
            ++digits;
        }
        bytes memory output = new bytes(digits);
        do {
            output[--digits] = bytes1(uint8(48 + value % 10));
            value /= 10;
        } while (digits != 0);
        return string(output);
    }
}
