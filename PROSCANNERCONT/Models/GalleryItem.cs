using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media.Imaging;
using System.Text.Json.Serialization;

namespace PROSCANNERCONT.Models
{
    public class GalleryItem : INotifyPropertyChanged
    {
        private BitmapSource? _screenshot;

        public string Id { get; set; } = Guid.NewGuid().ToString();
        public DateTime Timestamp { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string PageType { get; set; } = string.Empty;
        public bool IsManual { get; set; }

        [JsonIgnore]
        public BitmapSource? Screenshot
        {
            get => _screenshot;
            set
            {
                if (_screenshot != value)
                {
                    _screenshot = value;
                    OnPropertyChanged();
                }
            }
        }

        public string ScreenshotData { get; set; } = string.Empty;

        [JsonIgnore]
        public bool HasScreenshot => Screenshot != null;

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}