using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Altcha.AspNetCore;

/// <summary>Registers ALTCHA services.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>Adds ALTCHA services configured by <paramref name="configure"/>.</summary>
    public static IServiceCollection AddAltcha(this IServiceCollection services, Action<AltchaOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        var builder = AddCore(services);
        if (configure is not null)
        {
            builder.Configure(configure);
        }

        return services;
    }

    /// <summary>Adds ALTCHA services bound to <paramref name="configurationSection"/> (typically <c>Altcha</c>).</summary>
    public static IServiceCollection AddAltcha(this IServiceCollection services, IConfiguration configurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configurationSection);
        AddCore(services).Bind(configurationSection);
        return services;
    }

    /// <summary>
    /// Replaces the in-memory replay store with <see cref="DistributedCacheAltchaReplayStore"/>.
    /// Requires an <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/> registration.
    /// </summary>
    public static IServiceCollection AddAltchaDistributedReplayStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Replace(ServiceDescriptor.Singleton<IAltchaReplayStore, DistributedCacheAltchaReplayStore>());
        return services;
    }

    private static OptionsBuilder<AltchaOptions> AddCore(IServiceCollection services)
    {
        var builder = services.AddOptions<AltchaOptions>();
        builder.ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<AltchaOptions>, AltchaOptionsValidator>());
        services.AddHttpClient(AltchaDefaults.SentinelHttpClientName);
        services.TryAddSingleton<IAltchaReplayStore, InMemoryAltchaReplayStore>();
        services.TryAddSingleton<IAltchaService, AltchaService>();
        return builder;
    }
}
