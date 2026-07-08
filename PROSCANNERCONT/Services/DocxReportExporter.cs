using System;
using System.Collections.Generic;
using System.Linq;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Generates a Word .docx report from scan data. Used when clients want to
    /// edit the deliverable (most pentest engagements do — the consultancy
    /// loads it, tweaks the executive summary, ships it).  Pure OpenXML SDK,
    /// no Microsoft Office dependency on the host.
    /// </summary>
    public static class DocxReportExporter
    {
        public static void GeneratePortScanReport(
            string target, IReadOnlyList<PortScanResult> results, string filePath,
            string? company = null)
        {
            using var doc = WordprocessingDocument.Create(filePath, WordprocessingDocumentType.Document);
            var main = doc.AddMainDocumentPart();
            main.Document = new Document();
            var body = main.Document.AppendChild(new Body());

            void Heading(string text, int size = 28)
                => body.AppendChild(MakeParagraph(text, bold: true, size: size, color: "1F4E79"));

            void Plain(string text, bool bold = false, string? colour = null)
                => body.AppendChild(MakeParagraph(text, bold: bold, size: 22, color: colour));

            Heading("Port Scan Report", 36);
            if (!string.IsNullOrEmpty(company)) Plain(company, bold: true);
            Plain($"Target: {target}");
            Plain($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm}");
            Plain("");

            var open = results.Where(r => r.IsOpen).ToList();
            Heading("Executive summary", 28);
            Plain($"Open ports: {open.Count}");
            Plain($"CVEs found: {open.Sum(r => r.VulnCount)}");
            Plain($"Critical: {open.Count(r => r.RiskLevel == "Critical")}, High: {open.Count(r => r.RiskLevel == "High")}");
            Plain("");

            Heading("Open ports", 28);
            var table = new Table();
            table.AppendChild(new TableProperties(
                new TableBorders(
                    new TopBorder    { Val = BorderValues.Single, Size = 4 },
                    new BottomBorder { Val = BorderValues.Single, Size = 4 },
                    new LeftBorder   { Val = BorderValues.Single, Size = 4 },
                    new RightBorder  { Val = BorderValues.Single, Size = 4 },
                    new InsideHorizontalBorder { Val = BorderValues.Single, Size = 4 },
                    new InsideVerticalBorder   { Val = BorderValues.Single, Size = 4 })));

            void Row(string[] cells, bool header = false)
            {
                var tr = new TableRow();
                foreach (var c in cells)
                {
                    var tc = new TableCell();
                    var p = MakeParagraph(c, bold: header, size: 20,
                        color: header ? "FFFFFF" : null);
                    if (header)
                        tc.AppendChild(new TableCellProperties(new Shading { Fill = "1F4E79" }));
                    tc.AppendChild(p);
                    tr.AppendChild(tc);
                }
                table.AppendChild(tr);
            }

            Row(new[] { "Port", "Proto", "Service", "Version", "Risk" }, header: true);
            foreach (var r in open)
                Row(new[] { r.Port.ToString(), r.Protocol ?? "", r.Service ?? "", r.Version ?? "", r.RiskLevel ?? "-" });
            body.AppendChild(table);

            // CVE detail
            foreach (var r in open.Where(r => (r.CveFindings?.Count ?? 0) > 0))
            {
                Plain("");
                Heading($"Port {r.Port} / {r.Service} — CVEs", 24);
                foreach (var cve in r.CveFindings!)
                {
                    Plain($"{cve.CveId} [{cve.Severity}]", bold: true,
                        colour: SeverityColor(cve.Severity));
                    Plain(cve.Summary ?? "");
                }
            }

            main.Document.Save();
            AppLogger.Log.Information("[Report] DOCX generated → {Path}", filePath);
        }

        private static Paragraph MakeParagraph(string text, bool bold = false, int size = 22, string? color = null)
        {
            var run = new Run();
            var props = new RunProperties();
            if (bold) props.AppendChild(new Bold());
            props.AppendChild(new FontSize { Val = size.ToString() });
            if (!string.IsNullOrEmpty(color))
                props.AppendChild(new Color { Val = color });
            run.AppendChild(props);
            run.AppendChild(new Text(text) { Space = SpaceProcessingModeValues.Preserve });
            var p = new Paragraph();
            p.AppendChild(run);
            return p;
        }

        private static string SeverityColor(string? sev) => sev switch
        {
            "Critical" => "B00000",
            "High"     => "C45911",
            "Medium"   => "BF8F00",
            "Low"      => "548235",
            _          => "404040",
        };
    }
}
