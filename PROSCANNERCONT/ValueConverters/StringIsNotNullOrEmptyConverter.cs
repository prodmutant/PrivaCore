using System.Globalization;
using System.Windows.Data;
using System.Windows;

public class StringIsNotNullOrEmptyConverter : IValueConverter
{
    public static StringIsNotNullOrEmptyConverter Instance { get; } = new StringIsNotNullOrEmptyConverter();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool hasValue = !string.IsNullOrEmpty(value?.ToString());

        // Check if we need to return Visibility
        if (targetType == typeof(Visibility) || parameter?.ToString() == "VisibleCollapsed")
        {
            return hasValue ? Visibility.Visible : Visibility.Collapsed;
        }

        return hasValue;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}