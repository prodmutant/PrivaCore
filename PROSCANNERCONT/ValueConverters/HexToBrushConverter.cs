using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace PROSCANNERCONT.ValueConverters
{
    /// <summary>Converts a "#RRGGBB" string to a SolidColorBrush (for data-bound colours).</summary>
    public class HexToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            try { return new SolidColorBrush((Color)ColorConverter.ConvertFromString(value?.ToString() ?? "#8B949E")); }
            catch { return Brushes.Gray; }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
