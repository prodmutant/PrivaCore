using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.NetworkInformation;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Net.Http;
using System.Text;
using System.Net.Sockets;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using PROSCANNERCONT.PortScanProtocols;
using System.IO;

namespace PROSCANNERCONT.Security
{
    public class SecurityCheck
    {
        private readonly ServiceDetector _serviceDetector;
        private readonly NVDChecker _nvdChecker;
        private MainWindow? _mainWindow;
        private const int CRITICAL_RISK = 30;
        private const int MEDIUM_RISK = 15;
        private const int LOW_RISK = 5;

        public SecurityCheck()
        {
            _serviceDetector = new ServiceDetector();
            _nvdChecker = new   NVDChecker();
        }

        public SecurityCheck(MainWindow mainWindow) : this()
        {
            _mainWindow = mainWindow;
        }

        public class SecurityIssue
        {
            public string  Category       { get; set; }
            public string  Description    { get; set; }
            public int     RiskScore      { get; set; }
            public string  Severity       { get; set; }
            public string  Recommendation { get; set; }
            /// <summary>Actual CVSS base score from NVD (0 when not available).</summary>
            public decimal CvssScore      { get; set; }
        }

        public class SecurityCheckResult
        {
            public int TotalScore { get; set; }
            public List<SecurityIssue> Issues { get; set; }
            public string RiskLevel => TotalScore switch
            {
                > 50 => "High Risk",
                > 30 => "Medium Risk",
                _ => "Low Risk"
            };
        }

        public async Task<SecurityCheckResult> PerformSecurityCheck(string host)
        {
            var issues = new List<SecurityIssue>();
            var result = new SecurityCheckResult { Issues = issues };

            // Your existing checks here...
            await CheckNetworkSecurity(host, issues);
            CheckSystemSecurity(issues);
            CheckUserAuthentication(issues);

            // Calculate total score
            result.TotalScore = issues.Sum(i => i.RiskScore);

            // Get AI recommendations
            await GetAIRecommendations(issues);

            return result;
        }

        private async Task CheckNetworkSecurity(string host, List<SecurityIssue> issues)
        {
            // Common ports to check
            var commonPorts = new[] { 21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080 };
            foreach (var port in commonPorts)
            {
                try
                {
                    using var client = new TcpClient();
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                    await client.ConnectAsync(host, port, cts.Token);

                    if (client.Connected)
                    {
                        // Detect service and version
                        var (serviceName, version) = await _serviceDetector.DetectService(host, port);

                        // Check for vulnerabilities
                        var vulnerabilities = await _nvdChecker.CheckServiceVulnerabilities(serviceName, version);
                        issues.AddRange(vulnerabilities);

                        // Add open port as a potential risk
                        issues.Add(new SecurityIssue
                        {
                            Category = "Network",
                            Description = $"Port {port} is open running {serviceName} {version}",
                            RiskScore = MEDIUM_RISK,
                            Severity = "Medium",
                            Recommendation = $"Verify if port {port} needs to be open and ensure {serviceName} is properly secured"
                        });
                    }
                }
                catch
                {
                    // Port is closed or filtered
                    continue;
                }
            }

            // Check firewall status
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "advfirewall show allprofiles",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                if (!output.Contains("ON"))
                {
                    issues.Add(new SecurityIssue
                    {
                        Category = "Network",
                        Description = "Windows Firewall appears to be disabled",
                        RiskScore = CRITICAL_RISK,
                        Severity = "Critical",
                        Recommendation = "Enable Windows Firewall for all profiles"
                    });
                }
            }
            catch
            {
                // Firewall check failed 
            }

            // Check shared folders
            try
            {
                var shares = Directory.GetDirectories(@"\\localhost\ADMIN$");
                if (shares.Length > 0)
                {
                    issues.Add(new SecurityIssue
                    {
                        Category = "Network",
                        Description = "Administrative shares are accessible",
                        RiskScore = MEDIUM_RISK,
                        Severity = "Medium",
                        Recommendation = "Review and secure administrative shares if not needed"
                    });
                }
            }
            catch
            {
                // Share access check failed 
            }

            // Check Remote Desktop status
            try
            {
                var rdpKey = @"System\CurrentControlSet\Control\Terminal Server";
                using var key = Registry.LocalMachine.OpenSubKey(rdpKey);
                if (key != null)
                {
                    var rdpStatus = key.GetValue("fDenyTSConnections");
                    if (rdpStatus != null && rdpStatus.ToString() == "0")
                    {
                        issues.Add(new SecurityIssue
                        {
                            Category = "Network",
                            Description = "Remote Desktop is enabled",
                            RiskScore = MEDIUM_RISK,
                            Severity = "Medium",
                            Recommendation = "Disable Remote Desktop if not needed, or ensure it's properly secured"
                        });
                    }
                }
            }
            catch
            {
                // RDP check failed 
            }
        }

        private void CheckSystemSecurity(List<SecurityIssue> issues)
        {
            try
            {
                // Check running processes for known vulnerable software
                var processes = Process.GetProcesses();
                var knownVulnerableProcesses = new Dictionary<string, string>
            {
                { "telnet", "Use SSH instead" },
                { "ftp", "Use SFTP or FTPS instead" },
                { "vnc", "Use RDP with encryption or VPN" }
            };

                foreach (var process in processes)
                {
                    if (knownVulnerableProcesses.Keys.Contains(process.ProcessName.ToLower()))
                    {
                        issues.Add(new SecurityIssue
                        {
                            Category = "System",
                            Description = $"Potentially vulnerable process running: {process.ProcessName}",
                            RiskScore = CRITICAL_RISK,
                            Severity = "Critical",
                            Recommendation = knownVulnerableProcesses[process.ProcessName.ToLower()]
                        });
                    }
                }

                // Check antivirus status
                try
                {
                    var antivirusKey = @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";
                    using var key = Registry.LocalMachine.OpenSubKey(antivirusKey);
                    if (key != null)
                    {
                        var rtStatus = key.GetValue("DisableRealtimeMonitoring");
                        if (rtStatus != null && rtStatus.ToString() == "1")
                        {
                            issues.Add(new SecurityIssue
                            {
                                Category = "System",
                                Description = "Windows Defender real-time protection is disabled",
                                RiskScore = CRITICAL_RISK,
                                Severity = "Critical",
                                Recommendation = "Enable Windows Defender real-time protection"
                            });
                        }
                    }
                }
                catch { /* Registry access might be restricted */ }
            }
            catch (Exception ex)
            {
                issues.Add(new SecurityIssue
                {
                    Category = "System",
                    Description = $"Error during system security check: {ex.Message}",
                    RiskScore = LOW_RISK,
                    Severity = "Low",
                    Recommendation = "Some system checks could not be completed. Run as administrator for full access."
                });
            }
        }

        private void CheckUserAuthentication(List<SecurityIssue> issues)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = "accounts",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                if (!output.Contains("Minimum password length") ||
                    output.Contains("password length:") &&
                    int.Parse(output.Split(new[] { "password length:" }, StringSplitOptions.None)[1].Trim().Split('\n')[0]) < 12)
                {
                    issues.Add(new SecurityIssue
                    {
                        Category = "Authentication",
                        Description = "Weak password policy detected",
                        RiskScore = CRITICAL_RISK,
                        Severity = "Critical",
                        Recommendation = "Set minimum password length to 12 characters"
                    });
                }
            }
            catch { /* Password policy check failed */ }
        }
        private async Task GetAIRecommendations(List<SecurityIssue> issues)
        {
            try
            {
                var issuesSummary = string.Join("\n", issues.Select(i =>
                    $"Issue: {i.Description}\nCategory: {i.Category}\nSeverity: {i.Severity}"));

                var requestBody = new
                {
                    model = "gpt-3.5-turbo",
                    messages = new[]
                    {
                    new { role = "system", content = "You are a cybersecurity expert assistant. Provide detailed, actionable recommendations for security issues. Focus on practical steps and best practices.note that i  dont want you to use any thing to make the text larger or anything since this is a chatbox also talk as if you are a human chatting not a bot as much as you can you can use different lingo if you need" },
                    new { role = "user", content = $"Analyze these security issues and provide detailed recommendations for each:\n\n{issuesSummary}" }
                },
                    temperature = 0.7
                };

                using var httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {MainWindow.ApiKey}");

                var content = new StringContent(
                    JsonSerializer.Serialize(requestBody),
                    Encoding.UTF8,
                    "application/json"
                );

                var response = await httpClient.PostAsync(MainWindow.ApiEndpoint, content);
                var responseBody = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode && _mainWindow != null)
                {
                    using JsonDocument document = JsonDocument.Parse(responseBody);
                    var choices = document.RootElement.GetProperty("choices");
                    var firstChoice = choices[0];
                    var messageContent = firstChoice.GetProperty("message")
                                                  .GetProperty("content")
                                                  .GetString();

                    _mainWindow.AddAssistantMessage("📊 Security Check Results Analysis:\n\n" + messageContent);
                }
            }
            catch (Exception ex)
            {
                if (_mainWindow != null)
                {
                    _mainWindow.AddAssistantMessage($"Error getting AI recommendations: {ex.Message}");
                }
            }
        }
    }
}