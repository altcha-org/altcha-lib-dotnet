namespace Altcha;

/// <summary>
/// A parsed hex key prefix, matched case-insensitively (the prefix is normalized to lowercase, like the key hex).
/// Odd-length prefixes are supported: the trailing hex digit is matched against the high nibble of the next key byte.
/// </summary>
internal readonly struct KeyPrefix
{
    private readonly byte[] _bytes;
    private readonly byte _nibble;
    private readonly bool _hasNibble;

    private KeyPrefix(byte[] bytes, byte nibble, bool hasNibble)
    {
        _bytes = bytes;
        _nibble = nibble;
        _hasNibble = hasNibble;
    }

    public static KeyPrefix Parse(string? hex) =>
        TryParse(hex, out var prefix) ? prefix : throw new AltchaException("Invalid key prefix hex.");

    public static bool TryParse(string? hex, out KeyPrefix prefix)
    {
        prefix = default;
        hex ??= string.Empty;
        var even = hex.Length & ~1;
        if (!AltchaCrypto.TryFromHex(hex[..even], out var bytes))
        {
            return false;
        }

        if (even == hex.Length)
        {
            prefix = new KeyPrefix(bytes, 0, false);
            return true;
        }

        var last = hex[even];
        if (!char.IsAsciiHexDigit(last))
        {
            return false;
        }

        // `| 0x20` lowercases A-F.
        var nibble = char.IsAsciiDigit(last) ? last - '0' : (last | 0x20) - 'a' + 10;
        prefix = new KeyPrefix(bytes, (byte)(nibble << 4), true);
        return true;
    }

    public bool Matches(ReadOnlySpan<byte> key)
    {
        var bytes = _bytes ?? [];
        if (!key.StartsWith(bytes))
        {
            return false;
        }

        return !_hasNibble || (key.Length > bytes.Length && (key[bytes.Length] & 0xf0) == _nibble);
    }
}
