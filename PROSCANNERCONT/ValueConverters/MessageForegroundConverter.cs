using System;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace PROSCANNERCONT.ValueConverters
{
    public class MessageForegroundConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            // User messages sit on AccentBrush — always use white text for contrast.
            // Bot messages sit on SecondaryBackgroundBrush — use theme TextBrush.
            bool isUser = value is bool b && b;
            if (isUser)
                return new SolidColorBrush(Colors.White);
            return Application.Current.Resources["TextBrush"] as SolidColorBrush
                   ?? new SolidColorBrush(Colors.Black);
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
            => Binding.DoNothing;
    }
}
