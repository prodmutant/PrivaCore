using System;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace PROSCANNERCONT.ValueConverters
{
    public class MessageBackgroundConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            bool isUser = value is bool b && b;
            if (isUser)
                // User bubble: accent color so it clearly reads as "sent"
                return Application.Current.Resources["AccentBrush"] as SolidColorBrush
                       ?? new SolidColorBrush(Colors.SteelBlue);
            // Bot bubble: card background — distinct from page bg but not jarring
            return Application.Current.Resources["SecondaryBackgroundBrush"] as SolidColorBrush
                   ?? new SolidColorBrush(Colors.LightGray);
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
            => Binding.DoNothing;
    }
}