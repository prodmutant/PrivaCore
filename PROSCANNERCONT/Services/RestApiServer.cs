using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Optional read-only REST API for the desktop app. Binds to
    /// http://127.0.0.1:{port}/ by default (localhost only — no exposure
    /// outside the box) and requires an API key header. Used by:
    ///   • The companion web app to mirror live state
    ///   • CI/CD pipelines that want to query "is host X clean?" mid-deploy
    ///   • Power-user shell scripts (curl + jq)
    ///
    /// Pure HttpListener to avoid the 30 MB Kestrel dependency for a tiny
    /// localhost endpoint set.
    /// </summary>
    public sealed class RestApiServer : IDisposable
    {
        private HttpListener? _listener;
        private CancellationTokenSource? _cts;

        public int Port { get; set; } = 8765;
        public bool BindAllInterfaces { get; set; } = false;
        public string ApiKey { get; set; } = "";
        public bool IsRunning => _listener?.IsListening ?? false;

        public void Start()
        {
            if (IsRunning) return;
            if (string.IsNullOrEmpty(ApiKey))
                ApiKey = Guid.NewGuid().ToString("N").Substring(0, 32);

            var host = BindAllInterfaces ? "+" : "127.0.0.1";
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://{host}:{Port}/");
            try
            {
                _listener.Start();
            }
            catch (HttpListenerException ex)
            {
                AppLogger.Log.Error(ex, "[Api] failed to start (try running as admin or use a free port)");
                throw;
            }

            _cts = new CancellationTokenSource();
            _ = Task.Run(() => Loop(_cts.Token));
            AppLogger.Log.Information("[Api] listening on port {Port} (key={KeyMask})",
                Port, ApiKey.Substring(0, Math.Min(6, ApiKey.Length)) + "…");
        }

        public void Stop()
        {
            _cts?.Cancel();
            try { _listener?.Stop(); _listener?.Close(); } catch { }
            _listener = null;
        }

        private async Task Loop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && _listener != null)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync().ConfigureAwait(false); }
                catch { break; }
                _ = Task.Run(() => HandleAsync(ctx));
            }
        }

        private async Task HandleAsync(HttpListenerContext ctx)
        {
            try
            {
                // Auth
                var key = ctx.Request.Headers["X-API-Key"];
                if (!string.Equals(key, ApiKey, StringComparison.Ordinal))
                {
                    await Reply(ctx, 401, new { error = "unauthorized" });
                    return;
                }

                var path = ctx.Request.Url?.AbsolutePath ?? "/";
                switch (path)
                {
                    case "/api/health":
                        await Reply(ctx, 200, new { ok = true, ts = DateTime.UtcNow });
                        break;
                    case "/api/scans":
                        await Reply(ctx, 200, StateService.Instance.RecentScanResults.ToList());
                        break;
                    case "/api/alerts":
                        await Reply(ctx, 200, IDSManager.Engine.Alerts.Take(200).ToList());
                        break;
                    case "/api/assets":
                        await Reply(ctx, 200, AssetInventoryService.Instance.Assets.ToList());
                        break;
                    case "/api/threats":
                        await Reply(ctx, 200, new
                        {
                            indicators = ThreatIntelService.Instance.TotalIndicators,
                            lastRefresh = ThreatIntelService.Instance.LastRefresh,
                        });
                        break;
                    case "/api/engagement":
                        await Reply(ctx, 200, EngagementService.Instance.Active);
                        break;
                    case "/api/certs/expiring":
                        await Reply(ctx, 200, CertExpiryMonitor.Instance.ExpiringSoon.ToList());
                        break;
                    default:
                        await Reply(ctx, 404, new { error = "not_found", hint = "see /api/health, /api/scans, /api/alerts, /api/assets, /api/threats, /api/engagement, /api/certs/expiring" });
                        break;
                }
            }
            catch (Exception ex)
            {
                AppLogger.Log.Warning(ex, "[Api] request handler error");
                try { await Reply(ctx, 500, new { error = ex.Message }); } catch { }
            }
        }

        private static async Task Reply(HttpListenerContext ctx, int status, object body)
        {
            ctx.Response.StatusCode = status;
            ctx.Response.ContentType = "application/json";
            ctx.Response.Headers["Access-Control-Allow-Origin"] = "*";
            var json = JsonSerializer.Serialize(body, new JsonSerializerOptions
            {
                WriteIndented = false,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            });
            var bytes = Encoding.UTF8.GetBytes(json);
            await ctx.Response.OutputStream.WriteAsync(bytes);
            ctx.Response.OutputStream.Close();
        }

        public void Dispose() => Stop();
    }
}
