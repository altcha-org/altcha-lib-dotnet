namespace Altcha;

/// <summary>Base exception for ALTCHA errors such as malformed challenges or unsupported algorithms.</summary>
public class AltchaException : Exception
{
    /// <summary>Creates an exception with the given message.</summary>
    public AltchaException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with the given message and inner exception.</summary>
    public AltchaException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Thrown when remote Sentinel verification fails after all retry attempts.</summary>
public class AltchaSentinelException : AltchaException
{
    /// <summary>Creates an exception with the given message and the last attempt's error.</summary>
    public AltchaSentinelException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Thrown when Sentinel responds with an unexpected (non-2xx, non-400) HTTP status.</summary>
public class AltchaHttpStatusException : AltchaException
{
    /// <summary>Creates an exception for the given HTTP status.</summary>
    public AltchaHttpStatusException(int statusCode, string? reasonPhrase)
        : base($"Unexpected HTTP status {statusCode}")
    {
        StatusCode = statusCode;
        ReasonPhrase = reasonPhrase;
    }

    /// <summary>The HTTP status code returned by Sentinel.</summary>
    public int StatusCode { get; }

    /// <summary>The HTTP reason phrase returned by Sentinel, if any.</summary>
    public string? ReasonPhrase { get; }
}
