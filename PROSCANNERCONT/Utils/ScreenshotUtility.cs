using System;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PROSCANNERCONT.Utils
{
    public static class ScreenshotUtility
    {
        public static BitmapSource? CapturePage(FrameworkElement element)
        {
            try
            {
                if (element == null) return null;

                // Ensure the element is properly measured and arranged
                element.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                element.Arrange(new Rect(element.DesiredSize));
                element.UpdateLayout();

                // Use the element's actual size, but ensure minimum dimensions
                var width = Math.Max(1, (int)element.ActualWidth);
                var height = Math.Max(1, (int)element.ActualHeight);

                var renderBitmap = new RenderTargetBitmap(
                    width,
                    height,
                    96, 96, PixelFormats.Pbgra32);

                renderBitmap.Render(element);
                renderBitmap.Freeze(); // Important: Freeze to make it thread-safe

                return renderBitmap;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"CapturePage error: {ex.Message}");
                return null;
            }
        }

        public static string BitmapToBase64(BitmapSource bitmap)
        {
            try
            {
                if (bitmap == null) return string.Empty;

                var encoder = new PngBitmapEncoder();
                encoder.Frames.Add(BitmapFrame.Create(bitmap));

                using var stream = new MemoryStream();
                encoder.Save(stream);
                byte[] bytes = stream.ToArray();

                // Add validation
                if (bytes.Length == 0)
                {
                    System.Diagnostics.Debug.WriteLine("BitmapToBase64: Encoded bytes array is empty");
                    return string.Empty;
                }

                string base64 = Convert.ToBase64String(bytes);
                System.Diagnostics.Debug.WriteLine($"BitmapToBase64: Successfully encoded {bytes.Length} bytes to {base64.Length} characters");
                return base64;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"BitmapToBase64 error: {ex.Message}");
                return string.Empty;
            }
        }

        public static BitmapSource? Base64ToBitmap(string base64)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(base64))
                {
                    System.Diagnostics.Debug.WriteLine("Base64ToBitmap: Input string is null or empty");
                    return null;
                }

                byte[] bytes = Convert.FromBase64String(base64);

                if (bytes.Length == 0)
                {
                    System.Diagnostics.Debug.WriteLine("Base64ToBitmap: Decoded bytes array is empty");
                    return null;
                }

                using var stream = new MemoryStream(bytes);
                var decoder = BitmapDecoder.Create(stream, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);

                if (decoder.Frames.Count == 0)
                {
                    System.Diagnostics.Debug.WriteLine("Base64ToBitmap: No frames found in decoded image");
                    return null;
                }

                var bitmap = decoder.Frames[0];
                bitmap.Freeze(); // Important: Freeze to make it thread-safe

                System.Diagnostics.Debug.WriteLine($"Base64ToBitmap: Successfully decoded {base64.Length} characters to {bytes.Length} bytes");
                return bitmap;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Base64ToBitmap error: {ex.Message}");
                return null;
            }
        }

        // NEW METHOD: Create a thumbnail version for better performance
        public static BitmapSource? CreateThumbnail(BitmapSource source, int maxWidth = 300, int maxHeight = 200)
        {
            try
            {
                if (source == null) return null;

                double scaleX = (double)maxWidth / source.PixelWidth;
                double scaleY = (double)maxHeight / source.PixelHeight;
                double scale = Math.Min(scaleX, scaleY);

                if (scale >= 1.0) return source; // No need to resize

                var transform = new ScaleTransform(scale, scale);
                var thumbnail = new TransformedBitmap(source, transform);
                thumbnail.Freeze();

                return thumbnail;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"CreateThumbnail error: {ex.Message}");
                return source; // Return original if thumbnail creation fails
            }
        }
    }
}