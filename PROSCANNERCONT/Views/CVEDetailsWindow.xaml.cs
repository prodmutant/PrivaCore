using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Effects;
using PROSCANNERCONT.Models;
using System.Text.Json;
using System.Text;
using System.Text.RegularExpressions;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// Interaction logic for CVEDetailsWindow.xaml
    /// Shows detailed CVE information for a specific port scan result with cost-effective AI normalization
    /// </summary>
    public partial class CVEDetailsWindow : Window
    {
        private PortScanResult _scanResult;
        private readonly HttpClient _httpClient;
        private readonly HttpClient _openAiClient;

        // Read the NVD API key from the user's configured secrets (Settings → Secrets)
        // or the NVD_API_KEY environment variable. NVD lookups also work without a key
        // at a lower rate limit, so this is optional.
        private readonly string _nvdApiKey = Services.SecretsManager.Get(Services.SecretsManager.KeyNvdApiKey);

        // Use the same OpenAI configuration from MainWindow
        private static readonly string OpenAiApiKey = MainWindow.ApiKey;
        private static readonly string OpenAiApiEndpoint = MainWindow.ApiEndpoint;

        // Cache for AI normalization results
        private readonly Dictionary<string, ServiceNormalizationResult> _normalizationCache;

        public CVEDetailsWindow(PortScanResult scanResult)
        {
            InitializeComponent();
            _scanResult = scanResult;
            _httpClient = new HttpClient();

            // Initialize OpenAI client
            _openAiClient = new HttpClient();
            _openAiClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {OpenAiApiKey}");

            _normalizationCache = new Dictionary<string, ServiceNormalizationResult>();

            // Set up the window
            LoadServiceInformation();
            _ = LoadCVEInformationAsync(); // Fire and forget async call
        }

        /// <summary>
        /// Handles dragging the window when clicking on the header
        /// </summary>
        private void HeaderGrid_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            try
            {
                if (e.ButtonState == System.Windows.Input.MouseButtonState.Pressed)
                {
                    this.DragMove();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Drag move error: {ex.Message}");
            }
        }

        /// <summary>
        /// Loads the basic service information into the UI
        /// </summary>
        private void LoadServiceInformation()
        {
            var serviceName = _scanResult.Service ?? "Unknown";
            var serviceVersion = _scanResult.Version ?? "Unknown";

            ServiceTitleTextBlock.Text = $"{serviceName} Vulnerability Analysis";
            ServiceInfoTextBlock.Text = $"AI-powered search for: {serviceName} {serviceVersion}";

            IPAddressTextBlock.Text = _scanResult.IPAddress;
            PortTextBlock.Text = _scanResult.Port.ToString();
            ServiceTextBlock.Text = serviceName;
            VersionTextBlock.Text = serviceVersion;
            ProtocolTextBlock.Text = _scanResult.Protocol ?? "Unknown";
        }

        /// <summary>
        /// Loads CVE information asynchronously with AI normalization
        /// </summary>
        private async Task LoadCVEInformationAsync()
        {
            try
            {
                // Show loading state
                LoadingPanel.Visibility = Visibility.Visible;
                CVEScrollViewer.Visibility = Visibility.Collapsed;
                NoCVEPanel.Visibility = Visibility.Collapsed;

                Console.WriteLine("\n" + new string('=', 60));
                Console.WriteLine($"🔍 CVE SEARCH STARTED");
                Console.WriteLine($"📥 Service: '{_scanResult.Service}'");
                Console.WriteLine($"📥 Version: '{_scanResult.Version}'");
                Console.WriteLine(new string('=', 60));

                // Use AI-powered CVE lookup
                var cveList = await SearchCVEsWithAI(_scanResult.Service, _scanResult.Version);

                Console.WriteLine($"\n✅ CVE SEARCH COMPLETE: {cveList.Count} vulnerabilities found");

                // Update UI on main thread
                Dispatcher.Invoke(() =>
                {
                    LoadingPanel.Visibility = Visibility.Collapsed;

                    if (cveList.Any())
                    {
                        CVECountTextBlock.Text = $"({cveList.Count} found)";
                        PopulateCVEList(cveList);
                        CVEScrollViewer.Visibility = Visibility.Visible;
                    }
                    else
                    {
                        CVECountTextBlock.Text = "(0 found)";
                        NoCVEPanel.Visibility = Visibility.Visible;
                    }
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"💥 CVE search failed: {ex.Message}");

                Dispatcher.Invoke(() =>
                {
                    LoadingPanel.Visibility = Visibility.Collapsed;
                    CVECountTextBlock.Text = "(Error loading)";

                    // Show error message
                    var errorPanel = new StackPanel
                    {
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center
                    };

                    var errorText = new TextBlock
                    {
                        Text = "Error loading vulnerability data",
                        Foreground = (Brush)FindResource("TextBrush"),
                        FontWeight = FontWeights.Medium,
                        HorizontalAlignment = HorizontalAlignment.Center
                    };

                    var errorDetail = new TextBlock
                    {
                        Text = ex.Message,
                        Foreground = (Brush)FindResource("TextBrush"),
                        Opacity = 0.7,
                        FontSize = 12,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        Margin = new Thickness(0, 5, 0, 0)
                    };

                    errorPanel.Children.Add(errorText);
                    errorPanel.Children.Add(errorDetail);

                    CVEListPanel.Children.Clear();
                    CVEListPanel.Children.Add(errorPanel);
                    CVEScrollViewer.Visibility = Visibility.Visible;
                });
            }
        }

        /// <summary>
        /// AI-powered CVE search with service normalization
        /// </summary>
        private async Task<List<CVEInfo>> SearchCVEsWithAI(string serviceName, string version)
        {
            var allCVEs = new List<CVEInfo>();

            try
            {
                // STEP 1: Test basic connectivity
                Console.WriteLine("\n🌐 Testing NVD API connectivity...");
                if (!await TestNVDConnectivity())
                {
                    Console.WriteLine("❌ NVD API not accessible");
                    return allCVEs;
                }
                Console.WriteLine("✅ NVD API is accessible");

                // STEP 2: Direct search (baseline)
                Console.WriteLine("\n🔍 STEP 1: Direct search...");
                var directResults = await QueryNVDForService(serviceName, version);
                Console.WriteLine($"📊 Direct search: {directResults.Count} CVEs");
                allCVEs.AddRange(directResults);

                // STEP 3: AI normalization
                Console.WriteLine("\n🤖 STEP 2: AI normalization...");
                var normalized = await NormalizeServiceWithAI(serviceName, version);

                Console.WriteLine($"🎯 AI Results:");
                Console.WriteLine($"   Primary: '{normalized.PrimaryServiceName}'");
                Console.WriteLine($"   Clean Version: '{normalized.CleanVersion}'");
                Console.WriteLine($"   Alternatives: [{string.Join(", ", normalized.AlternativeNames)}]");

                // STEP 4: Search with normalized terms
                Console.WriteLine("\n🔍 STEP 3: AI-enhanced searches...");

                // Search with primary service name
                if (normalized.PrimaryServiceName != serviceName)
                {
                    var primaryResults = await QueryNVDForService(normalized.PrimaryServiceName, normalized.CleanVersion);
                    Console.WriteLine($"📊 Primary search '{normalized.PrimaryServiceName}': {primaryResults.Count} CVEs");
                    allCVEs.AddRange(primaryResults);
                }

                // Search alternatives
                foreach (var altName in normalized.AlternativeNames.Take(2))
                {
                    var altResults = await QueryNVDForService(altName, normalized.CleanVersion);
                    Console.WriteLine($"📊 Alternative '{altName}': {altResults.Count} CVEs");
                    allCVEs.AddRange(altResults);
                }

                // Remove duplicates
                var uniqueCVEs = allCVEs
                    .GroupBy(cve => cve.CVE_ID)
                    .Select(group => group.First())
                    .OrderByDescending(cve => cve.Score)
                    .ToList();

                Console.WriteLine($"\n📈 FINAL: {allCVEs.Count} total → {uniqueCVEs.Count} unique CVEs");
                return uniqueCVEs;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"💥 AI CVE search error: {ex.Message}");
                return allCVEs;
            }
        }

        /// <summary>
        /// Cost-effective AI service normalization with minimal tokens
        /// </summary>
        private async Task<ServiceNormalizationResult> NormalizeServiceWithAI(string serviceName, string version)
        {
            var cacheKey = $"{serviceName}|{version}|{_scanResult.Port}";

            if (_normalizationCache.TryGetValue(cacheKey, out var cachedResult))
            {
                Console.WriteLine($"   💾 Cache hit");
                return cachedResult;
            }

            try
            {
                Console.WriteLine($"   🤖 AI call...");

                // Ultra-minimal prompt to save tokens
                var prompt = CreateMinimalPrompt(serviceName, version);

                var response = await CallOpenAI(prompt);
                Console.WriteLine($"   📝 Result: {response}");

                var result = ParseAIResponse(response);
                _normalizationCache[cacheKey] = result;
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ⚠️ AI failed, fallback");
                return CreatePortBasedFallback();
            }
        }

        /// <summary>
        /// Ultra-minimal prompt for cost efficiency
        /// </summary>
        private string CreateMinimalPrompt(string serviceName, string version)
        {
            // Super concise prompt - only essential info
            return $@"Port:{_scanResult.Port} Service:""{serviceName}"" Version:""{version}""

Convert to specific software name for CVE search.

JSON only:
{{""service"":""name"",""version"":""clean"",""alts"":[""alt1"",""alt2""]}}";
        }

        /// <summary>
        /// Cost-optimized OpenAI call with minimal tokens
        /// </summary>
        private async Task<string> CallOpenAI(string prompt)
        {
            var requestBody = new
            {
                model = "gpt-3.5-turbo",
                messages = new[]
                {
                    new { role = "user", content = prompt } // No system message to save tokens
                },
                max_tokens = 50, // Reduced from 150 to 50
                temperature = 0   // Deterministic responses
            };

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _openAiClient.PostAsync(OpenAiApiEndpoint, content);

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"API failed: {response.StatusCode}");
            }

            var responseContent = await response.Content.ReadAsStringAsync();
            using JsonDocument document = JsonDocument.Parse(responseContent);
            return document.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString() ?? "";
        }

        /// <summary>
        /// Parse minimal AI response format
        /// </summary>
        private ServiceNormalizationResult ParseAIResponse(string aiResponse)
        {
            try
            {
                var cleanResponse = aiResponse.Trim();
                if (cleanResponse.StartsWith("```")) cleanResponse = cleanResponse.Substring(7);
                if (cleanResponse.EndsWith("```")) cleanResponse = cleanResponse.Substring(0, cleanResponse.Length - 3);

                // Parse minimal JSON format
                var parsed = JsonSerializer.Deserialize<MinimalAIResponse>(cleanResponse, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (parsed != null && !string.IsNullOrEmpty(parsed.Service))
                {
                    return new ServiceNormalizationResult
                    {
                        PrimaryServiceName = parsed.Service,
                        CleanVersion = parsed.Version ?? "",
                        AlternativeNames = parsed.Alts ?? new List<string>()
                    };
                }
            }
            catch
            {
                // Silent fail - no logging to save processing
            }

            return CreatePortBasedFallback();
        }

        /// <summary>
        /// Fast port-based fallback (no AI cost)
        /// </summary>
        private ServiceNormalizationResult CreatePortBasedFallback()
        {
            var port = _scanResult.Port;
            var serviceName = _scanResult.Service?.ToLower() ?? "";
            var version = ExtractBasicVersion(_scanResult.Version);

            // Quick lookup table for common ports
            var (primary, alts) = port switch
            {
                21 => ("vsftpd", new[] { "ftp", "proftpd" }),
                22 => ("openssh", new[] { "ssh", "sshd" }),
                25 => ("postfix", new[] { "smtp", "sendmail" }),
                53 => ("bind", new[] { "dns", "named" }),
                80 => ("apache", new[] { "http", "nginx" }),
                110 => ("dovecot", new[] { "pop3" }),
                111 => ("rpcbind", new[] { "rpc", "portmap" }),
                143 => ("dovecot", new[] { "imap" }),
                443 => ("apache", new[] { "https", "nginx" }),
                1433 => ("mssql", new[] { "sqlserver" }),
                3306 => ("mysql", new[] { "mariadb" }),
                3389 => ("rdp", new[] { "terminal services" }),
                5432 => ("postgresql", new[] { "postgres" }),
                _ => (serviceName, new[] { serviceName })
            };

            return new ServiceNormalizationResult
            {
                PrimaryServiceName = primary,
                CleanVersion = version,
                AlternativeNames = alts.ToList()
            };
        }

        private string ExtractBasicVersion(string version)
        {
            if (string.IsNullOrEmpty(version) || version == "Unknown") return "";
            var cleaned = Regex.Replace(version, @"\s*\([^)]*\)", "");
            var versionMatch = Regex.Match(cleaned, @"(\d+(?:\.\d+)*(?:-\d+(?:\.\d+)*)?)");
            return versionMatch.Success ? versionMatch.Groups[1].Value : "";
        }

        private async Task<bool> TestNVDConnectivity()
        {
            try
            {
                var testUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=apache&resultsPerPage=1";
                var request = new HttpRequestMessage(HttpMethod.Get, testUrl);
                if (!string.IsNullOrWhiteSpace(_nvdApiKey))
                    request.Headers.Add("apiKey", _nvdApiKey);
                var response = await _httpClient.SendAsync(request);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        private async Task<List<CVEInfo>> QueryNVDForService(string serviceName, string serviceVersion)
        {
            if (string.IsNullOrEmpty(serviceName))
                return new List<CVEInfo>();

            try
            {
                var baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
                var searchParams = new List<string> { "resultsPerPage=20" };

                var searchTerm = serviceName;
                if (!string.IsNullOrEmpty(serviceVersion) && serviceVersion != "Unknown")
                {
                    searchTerm = $"{serviceName} {serviceVersion}";
                }

                searchParams.Add($"keywordSearch={Uri.EscapeDataString(searchTerm)}");
                var requestUrl = $"{baseUrl}?{string.Join("&", searchParams)}";

                Console.WriteLine($"   🌐 Querying: {searchTerm}");

                var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
                if (!string.IsNullOrWhiteSpace(_nvdApiKey))
                    request.Headers.Add("apiKey", _nvdApiKey.Trim());

                var response = await _httpClient.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"   ❌ NVD Error: {response.StatusCode}");
                    return new List<CVEInfo>();
                }

                var jsonContent = await response.Content.ReadAsStringAsync();
                return ParseNVDResponse(jsonContent);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   💥 Query error: {ex.Message}");
                return new List<CVEInfo>();
            }
        }

        private List<CVEInfo> ParseNVDResponse(string jsonResponse)
        {
            var cveList = new List<CVEInfo>();

            try
            {
                if (string.IsNullOrEmpty(jsonResponse) || !jsonResponse.Contains("vulnerabilities"))
                    return cveList;

                var vulnerabilitiesStart = jsonResponse.IndexOf("\"vulnerabilities\":[");
                if (vulnerabilitiesStart == -1)
                    return cveList;

                var vulnerabilitiesSection = jsonResponse.Substring(vulnerabilitiesStart);
                var cveEntries = vulnerabilitiesSection.Split(new string[] { "\"cve\":{" }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var cveEntry in cveEntries.Skip(1))
                {
                    try
                    {
                        var cveInfo = ParseSingleCVE(cveEntry);
                        if (cveInfo != null)
                        {
                            cveList.Add(cveInfo);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"   ⚠️ Parse error for single CVE: {ex.Message}");
                    }
                }

                Console.WriteLine($"   ✅ Parsed {cveList.Count} CVEs from response");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   💥 Parse error: {ex.Message}");
            }

            return cveList;
        }

        private CVEInfo ParseSingleCVE(string cveEntry)
        {
            try
            {
                var cveId = ExtractJsonValue(cveEntry, "\"id\":");
                if (string.IsNullOrEmpty(cveId)) return null;

                var description = ExtractJsonValue(cveEntry, "\"value\":");
                if (string.IsNullOrEmpty(description))
                    description = "No description available";

                var cvssScore = 0.0;
                var cvssString = ExtractJsonValue(cveEntry, "\"baseScore\":");
                if (!string.IsNullOrEmpty(cvssString))
                {
                    double.TryParse(cvssString, out cvssScore);
                }

                var severity = GetSeverityFromScore(cvssScore);

                var publishedDate = DateTime.Now;
                var publishedString = ExtractJsonValue(cveEntry, "\"published\":");
                if (!string.IsNullOrEmpty(publishedString))
                {
                    DateTime.TryParse(publishedString.Replace("T", " ").Replace("Z", ""), out publishedDate);
                }

                return new CVEInfo
                {
                    CVE_ID = cveId,
                    Description = description.Length > 500 ? description.Substring(0, 500) + "..." : description,
                    Severity = severity,
                    Score = cvssScore,
                    PublishedDate = publishedDate,
                    References = new List<string> { $"https://nvd.nist.gov/vuln/detail/{cveId}" }
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ⚠️ Single CVE parse error: {ex.Message}");
                return null;
            }
        }

        private string ExtractJsonValue(string json, string key)
        {
            try
            {
                var startIndex = json.IndexOf(key);
                if (startIndex == -1) return null;

                startIndex += key.Length;
                while (startIndex < json.Length && (json[startIndex] == ' ' || json[startIndex] == '"'))
                    startIndex++;

                var endIndex = startIndex;
                var inQuotes = json[startIndex - 1] == '"';

                if (inQuotes)
                {
                    while (endIndex < json.Length && json[endIndex] != '"')
                        endIndex++;
                }
                else
                {
                    while (endIndex < json.Length && json[endIndex] != ',' && json[endIndex] != '}' && json[endIndex] != ']')
                        endIndex++;
                }

                if (endIndex > startIndex)
                {
                    return json.Substring(startIndex, endIndex - startIndex).Trim();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ⚠️ JSON extract error for {key}: {ex.Message}");
            }

            return null;
        }

        private string GetSeverityFromScore(double score)
        {
            if (score >= 9.0) return "Critical";
            if (score >= 7.0) return "High";
            if (score >= 4.0) return "Medium";
            if (score > 0.0) return "Low";
            return "Unknown";
        }

        /// <summary>
        /// Populates the CVE list in the UI
        /// </summary>
        private void PopulateCVEList(List<CVEInfo> cveList)
        {
            CVEListPanel.Children.Clear();

            foreach (var cve in cveList.OrderByDescending(c => c.Score))
            {
                var cveCard = CreateCVECard(cve);
                CVEListPanel.Children.Add(cveCard);
            }
        }

        /// <summary>
        /// Creates a UI card for a single CVE
        /// </summary>
        private Border CreateCVECard(CVEInfo cve)
        {
            var card = new Border
            {
                Background = (Brush)FindResource("SecondaryBackgroundBrush"),
                CornerRadius = new CornerRadius(12, 12, 12, 12),
                Margin = new Thickness(0, 0, 0, 12),
                Padding = new Thickness(20, 16, 20, 16),
                Effect = new DropShadowEffect
                {
                    Color = Colors.Black,
                    Opacity = 0.1,
                    ShadowDepth = 4,
                    BlurRadius = 12,
                    Direction = 270
                }
            };

            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Header with CVE ID and Severity
            var headerPanel = new StackPanel { Orientation = Orientation.Horizontal };

            var cveIdText = new TextBlock
            {
                Text = cve.CVE_ID,
                Foreground = (Brush)FindResource("TextBrush"),
                FontWeight = FontWeights.SemiBold,
                FontSize = 14,
                VerticalAlignment = VerticalAlignment.Center
            };

            var severityBadge = new Border
            {
                CornerRadius = new CornerRadius(16, 16, 16, 16),
                Padding = new Thickness(12, 4, 12, 4),
                Margin = new Thickness(12, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center,
                Effect = new DropShadowEffect
                {
                    Color = Colors.Black,
                    Opacity = 0.15,
                    ShadowDepth = 2,
                    BlurRadius = 6,
                    Direction = 270
                }
            };

            var severityText = new TextBlock
            {
                Text = cve.Severity.ToUpper(),
                FontSize = 11,
                FontWeight = FontWeights.Bold
            };

            // Set severity colors
            switch (cve.Severity.ToLower())
            {
                case "critical":
                    severityBadge.Background = new SolidColorBrush(Color.FromRgb(220, 53, 69));
                    severityText.Foreground = Brushes.White;
                    break;
                case "high":
                    severityBadge.Background = new SolidColorBrush(Color.FromRgb(255, 193, 7));
                    severityText.Foreground = Brushes.Black;
                    break;
                case "medium":
                    severityBadge.Background = new SolidColorBrush(Color.FromRgb(255, 152, 0));
                    severityText.Foreground = Brushes.White;
                    break;
                default:
                    severityBadge.Background = new SolidColorBrush(Color.FromRgb(108, 117, 125));
                    severityText.Foreground = Brushes.White;
                    break;
            }

            severityBadge.Child = severityText;

            var scoreText = new TextBlock
            {
                Text = $"CVSS: {cve.Score:F1}",
                Foreground = (Brush)FindResource("TextBrush"),
                FontSize = 13,
                Margin = new Thickness(12, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center,
                Opacity = 0.8,
                FontWeight = FontWeights.Medium
            };

            headerPanel.Children.Add(cveIdText);
            headerPanel.Children.Add(severityBadge);
            headerPanel.Children.Add(scoreText);

            // Description
            var descriptionText = new TextBlock
            {
                Text = cve.Description,
                Foreground = (Brush)FindResource("TextBrush"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 12, 0, 0),
                FontSize = 13,
                Opacity = 0.9,
                LineHeight = 18
            };

            // Footer with date and link
            var footerPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 12, 0, 0) };

            var dateText = new TextBlock
            {
                Text = $"Published: {cve.PublishedDate.ToString("MMM dd, yyyy")}",
                Foreground = (Brush)FindResource("TextBrush"),
                FontSize = 12,
                Opacity = 0.6,
                VerticalAlignment = VerticalAlignment.Center
            };

            var linkButton = new Button
            {
                Content = "View Details",
                FontSize = 12,
                Padding = new Thickness(12, 6, 12, 6),
                Margin = new Thickness(12, 0, 0, 0),
                Tag = cve.References.FirstOrDefault(),
                Background = new SolidColorBrush(Color.FromArgb(40, 255, 255, 255)),
                Foreground = (Brush)FindResource("TextBrush"),
                BorderThickness = new Thickness(0, 0, 0, 0),
                Cursor = System.Windows.Input.Cursors.Hand
            };

            // Create a custom button template for modern styling
            var buttonTemplate = new ControlTemplate(typeof(Button));
            var buttonBorder = new FrameworkElementFactory(typeof(Border));
            buttonBorder.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));
            buttonBorder.SetValue(Border.CornerRadiusProperty, new CornerRadius(8, 8, 8, 8));
            buttonBorder.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Button.PaddingProperty));

            var contentPresenter = new FrameworkElementFactory(typeof(ContentPresenter));
            contentPresenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            contentPresenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);

            buttonBorder.AppendChild(contentPresenter);
            buttonTemplate.VisualTree = buttonBorder;

            linkButton.Template = buttonTemplate;

            linkButton.Click += (s, e) =>
            {
                if (linkButton.Tag is string url && !string.IsNullOrEmpty(url))
                {
                    try
                    {
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = url,
                            UseShellExecute = true
                        });
                    }
                    catch (Exception ex)
                    {
                        AppDialog.Show($"Could not open URL: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
            };

            footerPanel.Children.Add(dateText);
            footerPanel.Children.Add(linkButton);

            Grid.SetRow(headerPanel, 0);
            Grid.SetRow(descriptionText, 1);
            Grid.SetRow(footerPanel, 2);

            grid.Children.Add(headerPanel);
            grid.Children.Add(descriptionText);
            grid.Children.Add(footerPanel);

            card.Child = grid;
            return card;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void OKButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            await LoadCVEInformationAsync();
        }

        protected override void OnClosed(EventArgs e)
        {
            _httpClient?.Dispose();
            _openAiClient?.Dispose();
            base.OnClosed(e);
        }
    }

    /// <summary>
    /// Data model for AI service normalization
    /// </summary>
    public class ServiceNormalizationResult
    {
        public string PrimaryServiceName { get; set; } = "";
        public string CleanVersion { get; set; } = "";
        public List<string> AlternativeNames { get; set; } = new List<string>();
    }

    /// <summary>
    /// Minimal AI response structure to save tokens
    /// </summary>
    public class MinimalAIResponse
    {
        public string Service { get; set; } = "";
        public string Version { get; set; } = "";
        public List<string> Alts { get; set; } = new List<string>();
    }

    /// <summary>
    /// Represents CVE information
    /// </summary>
    public class CVEInfo
    {
        public string CVE_ID { get; set; } = "";
        public string Description { get; set; } = "";
        public string Severity { get; set; } = "";
        public double Score { get; set; }
        public DateTime PublishedDate { get; set; }
        public List<string> References { get; set; } = new List<string>();
    }
}


