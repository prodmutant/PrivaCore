using System;
using System.Windows;
using System.Windows.Data;

namespace PROSCANNERCONT.ValueConverters
{
    public class MessageAlignmentConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is bool isUser)
            {
                return isUser ? HorizontalAlignment.Right : HorizontalAlignment.Left;
            }
            return HorizontalAlignment.Left;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
            => Binding.DoNothing;
    }
}