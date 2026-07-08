using System;
using Microsoft.Extensions.DependencyInjection;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Composition root.  Builds the DI graph once on App.OnStartup and
    /// exposes a resolver so existing pages can opt-in to DI gradually:
    /// new code uses constructor injection; legacy code keeps calling
    /// SingletonService.Instance — both routes return the same instance.
    ///
    /// This is the foundation for the MVVM migration: ViewModels resolve
    /// their service dependencies through the container rather than reaching
    /// into static singletons, which is what makes them unit-testable.
    /// </summary>
    public static class ServiceContainer
    {
        private static IServiceProvider? _provider;

        public static IServiceProvider Provider
            => _provider ?? throw new InvalidOperationException("ServiceContainer not built. Call Build() in App.OnStartup.");

        public static T Get<T>() where T : notnull => Provider.GetRequiredService<T>();
        public static T? TryGet<T>() where T : class => Provider.GetService<T>();

        public static void Build()
        {
            if (_provider != null) return;
            var services = new ServiceCollection();
            Register(services);
            _provider = services.BuildServiceProvider();
        }

        private static void Register(IServiceCollection s)
        {
            // ── Existing singletons — exposed via DI so new code doesn't
            //    need to know about the .Instance pattern.
            s.AddSingleton(_ => StateService.Instance);
            // GalleryManager is a static type; consumers call its static methods directly.
            s.AddSingleton(_ => TrafficCaptureService.Instance);
            s.AddSingleton(_ => AssetInventoryService.Instance);
            s.AddSingleton(_ => ThreatIntelService.Instance);
            s.AddSingleton(_ => CertExpiryMonitor.Instance);
            s.AddSingleton(_ => EngagementService.Instance);
            s.AddSingleton(_ => ScheduleService.Instance);
            s.AddSingleton(_ => CredentialVault.Instance);
            s.AddSingleton(_ => LootCollector.Instance);
            s.AddSingleton(_ => NotificationDispatcher.Instance);
            s.AddSingleton(_ => IDSManager.Engine);

            // ── New, transient scanners — DI gives each caller a fresh
            //    instance, which is what they want (state-free scan engines).
            s.AddTransient<TlsScannerService>();
            s.AddTransient<WebScannerService>();
            s.AddTransient<WirelessScannerService>();
            s.AddTransient<ContainerScannerService>();
            s.AddTransient<EmailReconService>();
            s.AddTransient<AdReconService>();
            s.AddTransient<OsintService>();
            s.AddTransient<PcapReplayService>();
            s.AddTransient<YaraLiteScanner>();

            // ── REST server is a single shared listener.
            s.AddSingleton<RestApiServer>();

            // ── Auth / RBAC — same instances the static .Instance accessors return.
            s.AddSingleton(_ => Security.Auth.UserStore.Instance);
            s.AddSingleton(_ => Security.Auth.SessionService.Instance);
            s.AddSingleton<Security.Auth.IIdentityProvider>(_ => new Security.Auth.LocalIdentityProvider());
        }

        public static void Dispose()
        {
            if (_provider is IDisposable d) d.Dispose();
            _provider = null;
        }
    }
}
