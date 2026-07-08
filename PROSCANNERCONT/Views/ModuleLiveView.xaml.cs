using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using PROSCANNERCONT.Models;
using PrivaCore.ModuleSdk;

namespace PROSCANNERCONT.Views
{
    /// <summary>Live control surface for a connected remote module: streams its events in real time.</summary>
    public partial class ModuleLiveView : Page
    {
        private readonly ManagedModule _module;
        private readonly ModuleClient _client;
        private readonly ObservableCollection<LiveEvent> _events = new();
        private int _count;

        public ModuleLiveView(ManagedModule module, ModuleClient client)
        {
            InitializeComponent();
            _module = module;
            _client = client;

            ModuleIcon.Icon = module.Icon;
            TitleText.Text = module.DisplayName;
            StatusText.Text = $"Connected to {module.Host}:{module.Port} as {module.Username}";
            EventGrid.ItemsSource = _events;

            _client.EventReceived += OnEvent;
            _client.Disconnected += OnDisconnected;
            Unloaded += (_, _) => _client.EventReceived -= OnEvent;
        }

        private void OnEvent(ModuleMessage msg) => Dispatcher.BeginInvoke(() =>
        {
            var ev = new LiveEvent
            {
                Time = DateTime.Now.ToString("HH:mm:ss"),
                Severity = msg.Str("severity") ?? "info",
                Name = msg.EventName ?? "event",
                Details = msg.Str("message")
                          ?? (msg.Data != null ? string.Join("  ", msg.Data.Select(kv => $"{kv.Key}={kv.Value}")) : ""),
            };
            _events.Insert(0, ev);
            while (_events.Count > 500) _events.RemoveAt(_events.Count - 1);
            EventCount.Text = (++_count).ToString();
            LastEvent.Text = ev.Name;
        });

        private void OnDisconnected() => Dispatcher.BeginInvoke(() =>
        {
            StatusDot.Fill = (System.Windows.Media.Brush)FindResource("CriticalBrush");
            StatusText.Text = "Disconnected from module";
            _module.IsConnected = false;
        });

        private void Disconnect_Click(object sender, RoutedEventArgs e)
        {
            _client.Dispose();
            _module.LiveClient = null;
            _module.IsConnected = false;
            OnDisconnected();
        }
    }

    public class LiveEvent
    {
        public string Time { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Name { get; set; } = "";
        public string Details { get; set; } = "";
    }
}
