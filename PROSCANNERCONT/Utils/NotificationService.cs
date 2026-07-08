using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;

namespace PROSCANNERCONT.Utils
{
    public enum NotificationType { Info, Success, Warning, Error }

    public class NotificationEntry
    {
        public string Id        { get; set; } = Guid.NewGuid().ToString();
        public string Title     { get; set; } = string.Empty;
        public string Message   { get; set; } = string.Empty;
        public NotificationType Type { get; set; }
        public DateTime Timestamp    { get; set; } = DateTime.Now;
        public bool IsRead           { get; set; }

        public string TimeAgo
        {
            get
            {
                var d = DateTime.Now - Timestamp;
                if (d.TotalSeconds < 60)  return "just now";
                if (d.TotalMinutes < 60)  return $"{(int)d.TotalMinutes}m ago";
                if (d.TotalHours   < 24)  return $"{(int)d.TotalHours}h ago";
                return Timestamp.ToString("MMM d");
            }
        }

        public string AccentHex => Type switch
        {
            NotificationType.Success => "#56D364",
            NotificationType.Warning => "#E3B341",
            NotificationType.Error   => "#F85149",
            _                        => "#58A6FF"
        };
    }

    public static class NotificationService
    {
        private const int Max = 50;
        private static readonly List<NotificationEntry> _entries = new();
        private static readonly object _lock = new();

        public static event EventHandler<NotificationEntry>? NotificationAdded;
        public static event EventHandler? UnreadCountChanged;

        public static IReadOnlyList<NotificationEntry> Entries
        {
            get { lock (_lock) return _entries.ToList().AsReadOnly(); }
        }

        public static int UnreadCount
        {
            get { lock (_lock) return _entries.Count(e => !e.IsRead); }
        }

        public static void Add(string title, string message,
            NotificationType type = NotificationType.Info)
        {
            var entry = new NotificationEntry
            {
                Title   = title,
                Message = message,
                Type    = type
            };

            lock (_lock)
            {
                _entries.Insert(0, entry);
                if (_entries.Count > Max) _entries.RemoveAt(_entries.Count - 1);
            }

            Application.Current?.Dispatcher.InvokeAsync(() =>
            {
                NotificationAdded?.Invoke(null, entry);
                UnreadCountChanged?.Invoke(null, EventArgs.Empty);
            });
        }

        public static void MarkAllRead()
        {
            lock (_lock) foreach (var e in _entries) e.IsRead = true;
            Application.Current?.Dispatcher.InvokeAsync(() =>
                UnreadCountChanged?.Invoke(null, EventArgs.Empty));
        }

        public static void Clear()
        {
            lock (_lock) _entries.Clear();
            Application.Current?.Dispatcher.InvokeAsync(() =>
                UnreadCountChanged?.Invoke(null, EventArgs.Empty));
        }
    }
}
