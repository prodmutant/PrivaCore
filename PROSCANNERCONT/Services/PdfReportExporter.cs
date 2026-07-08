using System;
using System.Collections.Generic;
using System.Linq;
using PROSCANNERCONT.Models;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Generates native PDF reports from scan + alert data using QuestPDF.
    /// Replaces the prior "open the HTML report in a browser and print to PDF"
    /// workaround — bookmarkable headings, embedded tables, pagination handled.
    /// </summary>
    public static class PdfReportExporter
    {
        static PdfReportExporter()
        {
            // QuestPDF community licence — free for individuals + companies < $1M revenue.
            QuestPDF.Settings.License = LicenseType.Community;
        }

        public static void GeneratePortScanReport(
            string target, IReadOnlyList<PortScanResult> results, string filePath,
            string? company = null, string? logoText = null)
        {
            var doc = Document.Create(c =>
            {
                c.Page(p =>
                {
                    p.Size(PageSizes.A4);
                    p.Margin(36);
                    p.PageColor(Colors.White);
                    p.DefaultTextStyle(t => t.FontSize(10).FontFamily("Segoe UI"));

                    p.Header().Row(r =>
                    {
                        r.RelativeItem().Column(col =>
                        {
                            col.Item().Text(logoText ?? "🛡 PrivaCore").FontSize(20).Bold().FontColor(Colors.Blue.Darken3);
                            if (!string.IsNullOrEmpty(company))
                                col.Item().Text(company).FontSize(11).FontColor(Colors.Grey.Darken1);
                        });
                        r.ConstantItem(140).AlignRight().Column(col =>
                        {
                            col.Item().Text("Port Scan Report").Bold().FontSize(12);
                            col.Item().Text($"Target: {target}").FontSize(9);
                            col.Item().Text(DateTime.Now.ToString("yyyy-MM-dd HH:mm")).FontSize(9);
                        });
                    });

                    p.Content().PaddingVertical(10).Column(col =>
                    {
                        var open = results.Where(r => r.IsOpen).ToList();
                        int totalCves = open.Sum(r => r.VulnCount);
                        int critical = open.Count(r => r.RiskLevel == "Critical");
                        int high     = open.Count(r => r.RiskLevel == "High");
                        int medium   = open.Count(r => r.RiskLevel == "Medium");

                        col.Item().Text("Executive summary").Bold().FontSize(14);
                        col.Item().Padding(6).Background(Colors.Grey.Lighten4).Column(s =>
                        {
                            s.Item().Text($"Open ports:  {open.Count}");
                            s.Item().Text($"CVEs found:  {totalCves}");
                            s.Item().Text($"Critical:    {critical}  /  High: {high}  /  Medium: {medium}");
                        });

                        col.Item().PaddingTop(14).Text("Open ports").Bold().FontSize(14);
                        col.Item().Table(t =>
                        {
                            t.ColumnsDefinition(c2 =>
                            {
                                c2.ConstantColumn(60); c2.ConstantColumn(60); c2.RelativeColumn();
                                c2.RelativeColumn(); c2.ConstantColumn(60);
                            });
                            t.Header(h =>
                            {
                                foreach (var head in new[] { "Port", "Proto", "Service", "Version", "Risk" })
                                    h.Cell().Background(Colors.Blue.Darken2).Padding(4).Text(head).FontColor(Colors.White).Bold();
                            });
                            foreach (var r in open)
                            {
                                t.Cell().Padding(3).Text(r.Port.ToString());
                                t.Cell().Padding(3).Text(r.Protocol);
                                t.Cell().Padding(3).Text(r.Service ?? "");
                                t.Cell().Padding(3).Text(r.Version ?? "");
                                t.Cell().Padding(3).Text(r.RiskLevel ?? "-");
                            }
                        });

                        // CVE detail per port
                        foreach (var r in open.Where(r => (r.CveFindings?.Count ?? 0) > 0))
                        {
                            col.Item().PaddingTop(10).Text($"Port {r.Port} / {r.Service} — CVEs").Bold().FontSize(11);
                            foreach (var cve in r.CveFindings!)
                            {
                                col.Item().BorderLeft(2).BorderColor(SeverityColor(cve.Severity))
                                    .PaddingLeft(6).PaddingVertical(2)
                                    .Column(b =>
                                    {
                                        b.Item().Text($"{cve.CveId}  [{cve.Severity}]").Bold().FontSize(9);
                                        b.Item().Text(cve.Summary ?? "").FontSize(9).FontColor(Colors.Grey.Darken2);
                                    });
                            }
                        }
                    });

                    p.Footer().AlignRight().Text(t =>
                    {
                        t.Span("PrivaCore Desktop — for authorised security testing only.  Page ");
                        t.CurrentPageNumber(); t.Span(" / "); t.TotalPages();
                    });
                });
            });

            doc.GeneratePdf(filePath);
            AppLogger.Log.Information("[Report] PDF generated → {Path}", filePath);
        }

        private static string SeverityColor(string? sev) => sev switch
        {
            "Critical" => Colors.Red.Darken3,
            "High"     => Colors.Orange.Darken2,
            "Medium"   => Colors.Yellow.Darken3,
            "Low"      => Colors.Green.Darken1,
            _          => Colors.Grey.Darken1,
        };
    }
}
