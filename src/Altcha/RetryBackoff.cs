namespace Altcha;

/// <summary>Controls how the delay between Sentinel retry attempts grows.</summary>
public enum RetryBackoff
{
    /// <summary>The delay doubles after each attempt.</summary>
    Exponential,

    /// <summary>The delay stays constant.</summary>
    Fixed,
}
