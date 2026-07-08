using System;
using System.Text.RegularExpressions;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// A runtime / scripted field (ECS "runtime field"): a named field computed on the fly from a
    /// template that interpolates other fields via <c>{field.name}</c> placeholders. Computed at
    /// read time (no re-indexing), so it's immediately queryable in KQL and usable as a Discover
    /// column. Example: name <c>user.session</c>, template <c>{user.name}@{host.name}</c>.
    /// </summary>
    public sealed class SiemRuntimeField
    {
        public string Name { get; set; } = "";
        public string Template { get; set; } = "";
        public bool Enabled { get; set; } = true;

        private static readonly Regex Placeholder = new(@"\{([^{}]+)\}", RegexOptions.CultureInvariant);

        /// <summary>Compute this field's value for an event by interpolating its template. Missing fields → empty.</summary>
        public string Compute(SiemEvent e)
        {
            if (string.IsNullOrEmpty(Template)) return "";
            return Placeholder.Replace(Template, m => e.Get(m.Groups[1].Value.Trim()) ?? "");
        }

        public string Summary() => $"{Name} = {Template}";
    }
}
