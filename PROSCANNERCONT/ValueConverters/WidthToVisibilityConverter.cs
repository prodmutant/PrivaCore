using System;
using System.Windows;
using System.Windows.Data;

namespace PROSCANNERCONT.ValueConverters
{
    public class WidthToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is double width)
            {
                return width <= 100 ? Visibility.Collapsed : Visibility.Visible;
            }
            return Visibility.Visible;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
            => Binding.DoNothing;
    }

    public class WidthToCollapsedVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is double width)
                return width <= 100 ? Visibility.Visible : Visibility.Collapsed;
            return Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
            => Binding.DoNothing;
    }
}