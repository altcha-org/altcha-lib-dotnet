using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Distributed;

namespace Altcha.AspNetCore;

/// <summary>Records used payload ids so each verified payload is accepted only once.</summary>
public interface IAltchaReplayStore
{
    /// <summary>Claims <paramref name="key"/> until <paramref name="expiresAt"/>. Returns true only for the first claim.</summary>
    ValueTask<bool> TryClaimAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken);
}

/// <summary>Process-local replay store. Suitable for single-instance deployments.</summary>
public sealed class InMemoryAltchaReplayStore : IAltchaReplayStore
{
    private const int SweepInterval = 1024;

    private readonly ConcurrentDictionary<string, long> _entries = new(StringComparer.Ordinal);
    private int _claims;

    /// <inheritdoc />
    public ValueTask<bool> TryClaimAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (Interlocked.Increment(ref _claims) % SweepInterval == 0)
        {
            Sweep(now);
        }

        var expiry = expiresAt.ToUnixTimeMilliseconds();
        if (_entries.TryAdd(key, expiry))
        {
            return ValueTask.FromResult(true);
        }

        var claimed = _entries.TryGetValue(key, out var existing) && existing <= now && _entries.TryUpdate(key, expiry, existing);
        return ValueTask.FromResult(claimed);
    }

    private void Sweep(long now)
    {
        foreach (var entry in _entries)
        {
            if (entry.Value <= now)
            {
                _entries.TryRemove(entry);
            }
        }
    }
}

/// <summary>
/// Replay store backed by <see cref="IDistributedCache"/>, for multi-instance deployments.
/// The check-then-set is NOT atomic across instances: two concurrent requests carrying the same payload
/// on different instances may both succeed. Use a store with an atomic set-if-absent where that matters.
/// </summary>
public sealed class DistributedCacheAltchaReplayStore : IAltchaReplayStore
{
    private static readonly byte[] Marker = [1];

    private readonly IDistributedCache _cache;

    /// <summary>Creates a store over <paramref name="cache"/>.</summary>
    public DistributedCacheAltchaReplayStore(IDistributedCache cache)
    {
        ArgumentNullException.ThrowIfNull(cache);
        _cache = cache;
    }

    /// <inheritdoc />
    public async ValueTask<bool> TryClaimAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (await _cache.GetAsync(key, cancellationToken).ConfigureAwait(false) is not null)
        {
            return false;
        }

        await _cache.SetAsync(key, Marker, new DistributedCacheEntryOptions { AbsoluteExpiration = expiresAt }, cancellationToken)
            .ConfigureAwait(false);
        return true;
    }
}
