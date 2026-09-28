namespace Altcha;

/// <summary>
/// A parsed hex key prefix. Odd-length prefixes are supported: the trailing hex digit is matched
/// against the high nibble of the next key byte, mirroring the JS client's hex-string comparison.
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

    public static KeyPrefix Parse(string? hex)
    {
        hex ??= string.Empty;
        var even = hex.Length & ~1;
        if (!AltchaCrypto.TryFromHex(hex[..even], out var bytes))
        {
            throw new AltchaException("Invalid key prefix hex.");
        }

        if (even == hex.Length)
        {
            return new KeyPrefix(bytes, 0, false);
        }

        if (!AltchaCrypto.TryFromHex(hex[even..] + "0", out var nibble))
        {
            throw new AltchaException("Invalid key prefix hex.");
        }

        return new KeyPrefix(bytes, nibble[0], true);
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
