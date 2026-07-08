using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Shapes;
using System.Windows.Threading;
using FontAwesome.Sharp;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Security;
using PROSCANNERCONT.Services;

namespace PROSCANNERCONT.Views
{
    public partial class DashboardPage
    {
        // ── Widget data ───────────────────────────────────────────────────────────
        private List<DashboardWidget> _widgets = new();
        private readonly Dictionary<WidgetType, ScrollViewer> _widgetScrollers = new();

        // ── Canvas drag state ────────────────────────────────────────────────────
        private DashboardWidget _dragWidget;
        private Border          _dragSourceCard;
        private bool            _isDragging;
        private Point           _dragStartPos;
        private Point           _dragCardOffset;

        // ── Detach / re-dock state ────────────────────────────────────────────────
        private readonly Dictionary<WidgetType, Window> _detachedWindows = new();
        private readonly Dictionary<WidgetType, Window> _popOutWindows   = new();

        // ── Load / rebuild ────────────────────────────────────────────────────────
        private void LoadWidgets()
        {
            _widgets = WidgetService.Load();
            RebuildWidgetsPanel();
        }

        public void RebuildWidgetsPanel()
        {
            _widgetScrollers.Clear();
            WidgetsPanel.Children.Clear();
            AutoLayoutNewWidgets();

            foreach (var w in _widgets.Where(x => x.Visible && !_detachedWindows.ContainsKey(x.Type)).OrderBy(x => x.Order))
            {
                try
                {
                    var card = BuildWidgetCard(w);
                    if (card == null) continue;
                    Canvas.SetLeft(card, w.X ?? 0);
                    Canvas.SetTop(card,  w.Y ?? 0);
                    WidgetsPanel.Children.Add(card);
                }
                catch (Exception ex) { Debug.WriteLine($"[Widget] Build error {w.Type}: {ex.Message}"); }
            }

            if (!_widgets.Any(x => x.Visible))
            {
                var hint = new TextBlock
                {
                    Text = "No widgets visible — click Customize to add some.",
                    Foreground = W_TextBrush(), Opacity = 0.45, FontSize = 13
                };
                Canvas.SetLeft(hint, 0);
                Canvas.SetTop(hint, 24);
                WidgetsPanel.Children.Add(hint);
            }

            Dispatcher.BeginInvoke(UpdateCanvasSize, DispatcherPriority.Loaded);
        }

        // ── In-place widget content refresh (no card rebuild) ────────────────────
        public void RefreshAllWidgetContents()
        {
            foreach (var w in _widgets.Where(x => x.Visible && !_detachedWindows.ContainsKey(x.Type)))
                RefreshWidgetContent(w);
        }

        public void RefreshWidgetContent(DashboardWidget widget)
        {
            if (!_widgetScrollers.TryGetValue(widget.Type, out var scroller)) return;
            try
            {
                var fresh = BuildWidgetContent(widget);
                if (fresh != null) scroller.Content = fresh;
            }
            catch (Exception ex) { Debug.WriteLine($"[Widget] Content refresh {widget.Type}: {ex.Message}"); }
        }

        private void AutoLayoutNewWidgets()
        {
            const double PAD = 12;
            var toPlace = _widgets
                .Where(w => w.Visible && !_detachedWindows.ContainsKey(w.Type) && w.X == null)
                .OrderBy(w => w.Order)
                .ToList();
            if (!toPlace.Any()) return;

            double panelW = WidgetsPanel.ActualWidth > 10 ? WidgetsPanel.ActualWidth : 900;

            // Start below all already-positioned widgets
            double startY = 0;
            var placed = _widgets.Where(w => w.Visible && w.X != null).ToList();
            if (placed.Any())
                startY = placed.Max(w => (w.Y ?? 0) + (w.CustomHeight ?? 200)) + PAD;

            double x = 0, y = startY, rowH = 0;
            foreach (var w in toPlace)
            {
                double cardW = w.CustomWidth ?? DashboardWidget.WidthFor(w.Size);
                if (x + cardW > panelW - PAD && x > 0) { x = 0; y += rowH + PAD; rowH = 0; }
                w.X = x;
                w.Y = y;
                rowH = Math.Max(rowH, w.CustomHeight ?? 200);
                x   += cardW + PAD;
            }
        }

        private void UpdateCanvasSize()
        {
            double maxR = 0, maxB = 0;
            foreach (UIElement child in WidgetsPanel.Children)
            {
                if (child is not FrameworkElement fe) continue;
                double l = Canvas.GetLeft(fe); if (double.IsNaN(l)) l = 0;
                double t = Canvas.GetTop(fe);  if (double.IsNaN(t)) t = 0;
                double w = fe.ActualWidth  > 0 ? fe.ActualWidth  : (fe.Width  > 0 ? fe.Width  : 360);
                double h = fe.ActualHeight > 0 ? fe.ActualHeight : (fe.Height > 0 ? fe.Height : 200);
                maxR = Math.Max(maxR, l + w);
                maxB = Math.Max(maxB, t + h);
            }
            WidgetsPanel.Width  = Math.Max(maxR + 40, 900);
            WidgetsPanel.Height = Math.Max(maxB + 40, 600);
        }

        // ── Customize button ──────────────────────────────────────────────────────
        private void CustomizeDashboard_Click(object sender, RoutedEventArgs e)
        {
            var picker = new WidgetPickerWindow(_widgets) { Owner = Window.GetWindow(this) };
            if (picker.ShowDialog() == true && picker.Result != null)
            {
                // Merge: only update Visible from picker, preserve order/size/dimensions
                foreach (var updated in picker.Result)
                {
                    var existing = _widgets.FirstOrDefault(w => w.Type == updated.Type);
                    if (existing != null) existing.Visible = updated.Visible;
                }
                WidgetService.Save(_widgets);
                RebuildWidgetsPanel();
            }
        }

        // ── Widget card chrome ────────────────────────────────────────────────────
        private Border BuildWidgetCard(DashboardWidget widget)
        {
            var content = BuildWidgetContent(widget);
            if (content == null) return null;

            double width  = widget.CustomWidth  ?? DashboardWidget.WidthFor(widget.Size);
            double height = widget.CustomHeight ?? double.NaN;
            var card = new Border
            {
                Tag             = widget,
                Width           = width,
                Height          = height,
                MinWidth        = 200,
                MinHeight       = 80,
                Margin          = new Thickness(0, 0, 12, 12),
                Background      = W_SecBg(),
                BorderBrush     = W_Border(),
                BorderThickness = new Thickness(1),
                CornerRadius    = new CornerRadius(10),
                ClipToBounds    = true,
                Effect          = new DropShadowEffect { BlurRadius = 10, ShadowDepth = 2, Opacity = 0.12, Color = Colors.Black }
            };

            var dock = new DockPanel();

            // ── Title bar ─────────────────────────────────────────────────────────
            var titleBar = new Border
            {
                Background      = W_BgBrush(),
                BorderBrush     = W_Border(),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding         = new Thickness(8, 5, 6, 5),
                Cursor          = Cursors.SizeAll
            };

            var tg = new Grid();
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var grip = new IconBlock
            {
                Icon = IconChar.GripVertical, Width = 10, Height = 10,
                Foreground = new SolidColorBrush(Colors.Gray),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0), Opacity = 0.5
            };
            Grid.SetColumn(grip, 0);
            tg.Children.Add(grip);

            var titleLabel = new TextBlock
            {
                Text = DashboardWidget.DisplayName(widget.Type),
                FontSize = 11, FontWeight = FontWeights.SemiBold,
                Foreground = W_TextBrush(), VerticalAlignment = VerticalAlignment.Center, Opacity = 0.9
            };
            Grid.SetColumn(titleLabel, 1);
            tg.Children.Add(titleLabel);

            var popOutBtn = MakeHeaderBtn(IconChar.ArrowUpRightFromSquare, "Pop out to window");
            Grid.SetColumn(popOutBtn, 2);
            tg.Children.Add(popOutBtn);

            var closeBtn = MakeHeaderBtn(IconChar.Xmark, "Remove widget");
            Grid.SetColumn(closeBtn, 3);
            tg.Children.Add(closeBtn);

            titleBar.Child = tg;
            DockPanel.SetDock(titleBar, Dock.Top);
            dock.Children.Add(titleBar);

            // ── Resize grip (bottom-right corner) ────────────────────────────────
            var resizeThumb = new Thumb
            {
                Width = 16, Height = 16,
                HorizontalAlignment = HorizontalAlignment.Right,
                Background = Brushes.Transparent, BorderThickness = new Thickness(0),
                Cursor = Cursors.SizeNWSE, ToolTip = "Drag to resize",
                Template = BuildResizeThumbTemplate()
            };
            var resizeBar = new Border { Height = 16, Background = Brushes.Transparent, Child = resizeThumb };
            DockPanel.SetDock(resizeBar, Dock.Bottom);
            dock.Children.Add(resizeBar);

            var contentScroll = new ScrollViewer
            {
                Content = content,
                VerticalScrollBarVisibility   = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            };
            _widgetScrollers[widget.Type] = contentScroll;
            dock.Children.Add(contentScroll);
            card.Child = dock;

            // ── Button wiring ─────────────────────────────────────────────────────
            closeBtn.Click += (_, __) =>
            {
                var w = _widgets.FirstOrDefault(x => x.Type == widget.Type);
                if (w != null) { w.Visible = false; WidgetService.Save(_widgets); }
                RebuildWidgetsPanel();
            };

            popOutBtn.Click += (_, __) => PopOutWidget(widget);

            resizeThumb.DragDelta += (_, e) =>
            {
                double newW = Math.Max(200, card.ActualWidth  + e.HorizontalChange);
                double newH = Math.Max(80,  card.ActualHeight + e.VerticalChange);
                card.Width  = newW;
                card.Height = newH;

                var w = _widgets.FirstOrDefault(x => x.Type == widget.Type);
                if (w == null) return;
                w.CustomWidth  = newW;
                w.CustomHeight = newH;
                w.Size = newW < 300 ? WidgetSize.Small : newW < 450 ? WidgetSize.Medium : WidgetSize.Large;
                WidgetService.Save(_widgets);
                UpdateCanvasSize();
            };

            // ── Canvas drag wiring ────────────────────────────────────────────────
            titleBar.PreviewMouseLeftButtonDown += (_, e) =>
            {
                var src = e.OriginalSource as DependencyObject;
                while (src != null && !ReferenceEquals(src, titleBar))
                {
                    if (src is Button) return;
                    src = VisualTreeHelper.GetParent(src);
                }
                _dragStartPos   = e.GetPosition(Application.Current.MainWindow);
                _dragCardOffset = e.GetPosition(card);
                _dragWidget     = widget;
                _dragSourceCard = card;
                _isDragging     = false;
                titleBar.CaptureMouse();
                e.Handled = true;
            };

            titleBar.MouseMove += (_, e) =>
            {
                if (e.LeftButton != MouseButtonState.Pressed || _dragWidget != widget) return;
                var mw  = Application.Current.MainWindow;
                var pos = e.GetPosition(mw);

                if (!_isDragging)
                {
                    if (Math.Abs(pos.X - _dragStartPos.X) < 6 && Math.Abs(pos.Y - _dragStartPos.Y) < 6) return;
                    _isDragging = true;
                    Canvas.SetZIndex(card, 1000);
                    card.RenderTransformOrigin = new Point(0.5, 0.0);
                    var st = new ScaleTransform(1.0, 1.0);
                    card.RenderTransform = st;
                    var liftAnim = new DoubleAnimation(1.03, TimeSpan.FromMilliseconds(120))
                        { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
                    st.BeginAnimation(ScaleTransform.ScaleXProperty, liftAnim);
                    st.BeginAnimation(ScaleTransform.ScaleYProperty, liftAnim);
                    card.Effect = new DropShadowEffect { BlurRadius = 40, ShadowDepth = 10, Opacity = 0.30, Color = Colors.Black };
                }

                // Mouse crossed window edge → live detach
                if (pos.X < 0 || pos.Y < 0 || pos.X > mw.ActualWidth || pos.Y > mw.ActualHeight)
                {
                    var screen = mw.PointToScreen(pos);
                    ResetCardDragAppearance(card);
                    _isDragging = false; _dragWidget = null; _dragSourceCard = null;
                    titleBar.ReleaseMouseCapture();
                    DetachWidgetLive(widget, screen);
                    return;
                }

                var canvasPos = e.GetPosition(WidgetsPanel);
                Canvas.SetLeft(card, Math.Max(0, canvasPos.X - _dragCardOffset.X));
                Canvas.SetTop(card,  Math.Max(0, canvasPos.Y - _dragCardOffset.Y));
            };

            titleBar.PreviewMouseLeftButtonUp += (_, e) =>
            {
                if (_dragWidget != widget) return;
                titleBar.ReleaseMouseCapture();
                if (_isDragging) CommitCanvasDrop(card, widget);
                else             Canvas.SetZIndex(card, 0);
                _isDragging = false; _dragWidget = null; _dragSourceCard = null;
            };

            titleBar.LostMouseCapture += (_, __) =>
            {
                if (_dragWidget == widget)
                {
                    ResetCardDragAppearance(card);
                    _isDragging = false; _dragWidget = null; _dragSourceCard = null;
                }
            };

            return card;
        }

        private static Button MakeHeaderBtn(IconChar icon, string tooltip) => new Button
        {
            Width = 20, Height = 20,
            Background = Brushes.Transparent, BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand, Margin = new Thickness(2, 0, 0, 0), ToolTip = tooltip,
            Content = new IconBlock { Icon = icon, Foreground = new SolidColorBrush(Colors.Gray), Width = 9, Height = 9 }
        };

        // ── Canvas drag helpers ───────────────────────────────────────────────────
        private void CommitCanvasDrop(Border card, DashboardWidget widget)
        {
            const int SNAP = 16;
            double rawX  = Canvas.GetLeft(card);
            double rawY  = Canvas.GetTop(card);
            double snapX = Math.Max(0, Math.Round(rawX / SNAP) * SNAP);
            double snapY = Math.Max(0, Math.Round(rawY / SNAP) * SNAP);

            AnimateToPosition(card, snapX, snapY, 140);
            ResetCardDragAppearance(card);

            var w = _widgets.FirstOrDefault(x => x.Type == widget.Type);
            if (w != null) { w.X = snapX; w.Y = snapY; WidgetService.Save(_widgets); }

            Dispatcher.BeginInvoke(UpdateCanvasSize, DispatcherPriority.Background);
        }

        private static void AnimateToPosition(UIElement card, double toX, double toY, int ms)
        {
            var ease  = new CubicEase { EasingMode = EasingMode.EaseOut };
            var xAnim = new DoubleAnimation(toX, TimeSpan.FromMilliseconds(ms))
                { EasingFunction = ease, FillBehavior = FillBehavior.Stop };
            var yAnim = new DoubleAnimation(toY, TimeSpan.FromMilliseconds(ms))
                { EasingFunction = ease, FillBehavior = FillBehavior.Stop };
            xAnim.Completed += (_, __) => Canvas.SetLeft(card, toX);
            yAnim.Completed += (_, __) => Canvas.SetTop(card,  toY);
            card.BeginAnimation(Canvas.LeftProperty, xAnim);
            card.BeginAnimation(Canvas.TopProperty,  yAnim);
        }

        private static void ResetCardDragAppearance(Border card)
        {
            Canvas.SetZIndex(card, 0);
            card.Effect = new DropShadowEffect { BlurRadius = 10, ShadowDepth = 2, Opacity = 0.12, Color = Colors.Black };
            if (card.RenderTransform is ScaleTransform st)
            {
                var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
                var snapBack = new DoubleAnimation(1.0, TimeSpan.FromMilliseconds(150)) { EasingFunction = ease };
                snapBack.Completed += (_, __) => card.RenderTransform = null;
                st.BeginAnimation(ScaleTransform.ScaleXProperty, snapBack);
                st.BeginAnimation(ScaleTransform.ScaleYProperty, snapBack);
            }
        }

        // Called mid-drag when mouse crosses the window boundary — window follows
        // the cursor live until mouse button is released.
        private void DetachWidgetLive(DashboardWidget widget, Point screenPos)
        {
            if (_detachedWindows.TryGetValue(widget.Type, out var old)) { old.Close(); _detachedWindows.Remove(widget.Type); }

            var win = BuildDetachedWindow(widget, screenPos);
            _detachedWindows[widget.Type] = win;
            RebuildWidgetsPanel();
            win.Show();

            // Offset so the title bar sits under the cursor
            double offX = win.Width  / 2;
            double offY = 20;

            var timer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(8)
            };

            timer.Tick += (_, __) =>
            {
                if (Mouse.LeftButton == MouseButtonState.Released)
                {
                    timer.Stop();
                    return; // window stays floating; use dock button or drag title back to dock
                }

                try
                {
                    var curScreen = win.PointToScreen(Mouse.GetPosition(win));
                    win.Left = curScreen.X - offX;
                    win.Top  = curScreen.Y - offY;
                }
                catch { timer.Stop(); }
            };

            timer.Start();
        }

        private Window BuildDetachedWindow(DashboardWidget widget, Point screenPos)
        {
            double cardW = widget.CustomWidth  ?? DashboardWidget.WidthFor(widget.Size);
            double cardH = widget.CustomHeight ?? 300;

            var win = new Window
            {
                WindowStyle       = WindowStyle.None,
                AllowsTransparency = true,
                Background        = Brushes.Transparent,
                Width             = cardW + 8,
                Height            = cardH + 8,
                Left              = screenPos.X - cardW / 2,
                Top               = screenPos.Y - 20,
                ResizeMode        = ResizeMode.CanResize,
                ShowInTaskbar     = false
            };

            var accentBrush = Application.Current.Resources["AccentBrush"] as Brush ?? Brushes.CornflowerBlue;

            var cardBorder = new Border
            {
                Margin          = new Thickness(4),
                Background      = W_SecBg(),
                BorderBrush     = W_Border(),
                BorderThickness = new Thickness(1),
                CornerRadius    = new CornerRadius(10),
                ClipToBounds    = true,
                Effect          = new DropShadowEffect { BlurRadius = 22, ShadowDepth = 5, Opacity = 0.28, Color = Colors.Black }
            };

            var dock = new DockPanel();

            // ── Title bar ────────────────────────────────────────────────────────
            var titleBar = new Border
            {
                Background      = W_BgBrush(),
                BorderBrush     = W_Border(),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding         = new Thickness(8, 5, 6, 5),
                Cursor          = Cursors.SizeAll
            };
            var tg = new Grid();
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            tg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            tg.Children.Add(new IconBlock { Icon = IconChar.GripVertical, Width = 10, Height = 10, Foreground = new SolidColorBrush(Colors.Gray), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0), Opacity = 0.5 });
            var titleLbl = new TextBlock { Text = DashboardWidget.DisplayName(widget.Type), FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), VerticalAlignment = VerticalAlignment.Center, Opacity = 0.7 };
            Grid.SetColumn(titleLbl, 1);
            tg.Children.Add(titleLbl);

            var dockBtn  = MakeHeaderBtn(IconChar.ArrowDownLong,  "Drag back or click to dock");
            var closeBtn = MakeHeaderBtn(IconChar.Xmark, "Remove widget");
            Grid.SetColumn(dockBtn,  2);
            Grid.SetColumn(closeBtn, 3);
            tg.Children.Add(dockBtn);
            tg.Children.Add(closeBtn);

            titleBar.Child = tg;
            DockPanel.SetDock(titleBar, Dock.Top);
            dock.Children.Add(titleBar);

            // ── Resize grip ──────────────────────────────────────────────────────
            var resizeThumb = new Thumb
            {
                Width = 16, Height = 16, HorizontalAlignment = HorizontalAlignment.Right,
                Background = Brushes.Transparent, BorderThickness = new Thickness(0),
                Cursor = Cursors.SizeNWSE, ToolTip = "Drag to resize",
                Template = BuildResizeThumbTemplate()
            };
            var detachResizeBar = new Border { Height = 16, Background = Brushes.Transparent, Child = resizeThumb };
            DockPanel.SetDock(detachResizeBar, Dock.Bottom);
            dock.Children.Add(detachResizeBar);

            // ── Content ──────────────────────────────────────────────────────────
            dock.Children.Add(new ScrollViewer
            {
                Content = BuildWidgetContent(widget),
                VerticalScrollBarVisibility   = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            });

            cardBorder.Child = dock;
            win.Content = cardBorder;

            // ── Manual drag (title bar) ──────────────────────────────────────────
            bool floatDragging = false;
            Point floatOffset  = default;
            bool isOverMain    = false;

            titleBar.PreviewMouseLeftButtonDown += (_, e) =>
            {
                // Don't hijack clicks on the dock / close buttons inside the title bar.
                var src = e.OriginalSource as DependencyObject;
                while (src != null && !ReferenceEquals(src, titleBar))
                {
                    if (src is Button) return;
                    src = VisualTreeHelper.GetParent(src);
                }
                floatOffset  = titleBar.PointToScreen(e.GetPosition(titleBar));
                floatOffset  = new Point(floatOffset.X - win.Left, floatOffset.Y - win.Top);
                floatDragging = true;
                titleBar.CaptureMouse();
                e.Handled = true;
            };

            titleBar.MouseMove += (_, e) =>
            {
                if (!floatDragging || e.LeftButton != MouseButtonState.Pressed) return;
                var cur = titleBar.PointToScreen(e.GetPosition(titleBar));
                win.Left = cur.X - floatOffset.X;
                win.Top  = cur.Y - floatOffset.Y;
            };

            titleBar.PreviewMouseLeftButtonUp += (_, e) =>
            {
                if (!floatDragging) return;
                titleBar.ReleaseMouseCapture();
                floatDragging = false;
                if (isOverMain)
                {
                    var dropScreen = new Point(win.Left + win.Width / 2, win.Top + win.Height / 2);
                    win.Close();
                    Dispatcher.BeginInvoke(() => DockWidgetAt(widget, dropScreen));
                }
                e.Handled = true;
            };

            titleBar.LostMouseCapture += (_, __) => floatDragging = false;

            // ── Hover detection → accent border when over main window ───────────
            win.LocationChanged += (_, __) =>
            {
                var mw = Application.Current.MainWindow;
                if (mw == null) return;
                var center = new Point(win.Left + win.Width / 2, win.Top + win.Height / 2);
                isOverMain = new Rect(mw.Left, mw.Top, mw.ActualWidth, mw.ActualHeight).Contains(center);

                cardBorder.BorderBrush     = isOverMain ? accentBrush : W_Border();
                cardBorder.BorderThickness = isOverMain ? new Thickness(2) : new Thickness(1);
            };

            // ── Resize ───────────────────────────────────────────────────────────
            resizeThumb.DragDelta += (_, e) =>
            {
                win.Width  = Math.Max(216, win.Width  + e.HorizontalChange);
                win.Height = Math.Max(108, win.Height + e.VerticalChange);
                var w = _widgets.FirstOrDefault(x => x.Type == widget.Type);
                if (w != null) { w.CustomWidth = win.Width - 8; w.CustomHeight = win.Height - 8; WidgetService.Save(_widgets); }
            };

            // ── Button actions ───────────────────────────────────────────────────
            dockBtn.Click += (_, __) =>
            {
                win.Close();
                DockWidgetAt(widget);
            };

            closeBtn.Click += (_, __) =>
            {
                win.Close();
                var w = _widgets.FirstOrDefault(x => x.Type == widget.Type);
                if (w != null) { w.Visible = false; WidgetService.Save(_widgets); }
            };

            win.Closed += (_, __) => _detachedWindows.Remove(widget.Type);

            return win;
        }

        // ── Re-dock: bring a detached widget back onto the canvas ────────────────
        private void DockWidgetAt(DashboardWidget widget, Point? screenDropPos = null)
        {
            _detachedWindows.Remove(widget.Type);

            if (screenDropPos.HasValue)
            {
                try
                {
                    var panelPos = WidgetsPanel.PointFromScreen(screenDropPos.Value);
                    double cardW = widget.CustomWidth ?? DashboardWidget.WidthFor(widget.Size);
                    widget.X = Math.Max(0, panelPos.X - cardW / 2);
                    widget.Y = Math.Max(0, panelPos.Y - 20);
                }
                catch { widget.X = null; widget.Y = null; }
            }
            else
            {
                widget.X = null;
                widget.Y = null;
            }

            WidgetService.Save(_widgets);
            RebuildWidgetsPanel();
        }

        // ── Resize thumb template ─────────────────────────────────────────────────
        private static ControlTemplate BuildResizeThumbTemplate()
        {
            var template = new ControlTemplate(typeof(Thumb));
            var factory  = new FrameworkElementFactory(typeof(Border));
            factory.SetValue(Border.BackgroundProperty,            Brushes.Transparent);
            factory.SetValue(Border.HorizontalAlignmentProperty,  HorizontalAlignment.Right);
            factory.SetValue(Border.VerticalAlignmentProperty,    VerticalAlignment.Bottom);
            factory.SetValue(FrameworkElement.WidthProperty,      16.0);
            factory.SetValue(FrameworkElement.HeightProperty,     16.0);

            var canvas = new FrameworkElementFactory(typeof(Canvas));
            canvas.SetValue(FrameworkElement.WidthProperty,  16.0);
            canvas.SetValue(FrameworkElement.HeightProperty, 16.0);

            var dotColor = new SolidColorBrush(Color.FromArgb(100, 150, 150, 150));
            foreach (var (cx, cy) in new[] { (10.0, 6.0), (14.0, 6.0), (14.0, 10.0), (10.0, 10.0), (14.0, 14.0), (10.0, 14.0) })
            {
                var dot = new FrameworkElementFactory(typeof(Ellipse));
                dot.SetValue(FrameworkElement.WidthProperty,  2.0);
                dot.SetValue(FrameworkElement.HeightProperty, 2.0);
                dot.SetValue(Shape.FillProperty,              dotColor);
                dot.SetValue(Canvas.LeftProperty,             cx);
                dot.SetValue(Canvas.TopProperty,              cy);
                canvas.AppendChild(dot);
            }

            factory.AppendChild(canvas);
            template.VisualTree = factory;
            return template;
        }

        // ── Pop-out to floating window ────────────────────────────────────────────
        private void PopOutWidget(DashboardWidget widget)
        {
            // Bring existing pop-out to front instead of opening a duplicate.
            if (_popOutWindows.TryGetValue(widget.Type, out var existing) && existing != null)
            {
                existing.Activate();
                return;
            }

            var content = BuildWidgetContent(widget);
            if (content == null) return;

            double fw = Math.Max(280, DashboardWidget.WidthFor(widget.Size) + 32);
            var win = new Window
            {
                Title       = DashboardWidget.DisplayName(widget.Type),
                Width       = fw,  Height    = 360,
                MinWidth    = 240, MinHeight = 180,
                WindowStyle = WindowStyle.ToolWindow,
                ResizeMode  = ResizeMode.CanResize,
                Owner       = Application.Current.MainWindow,
                Background  = W_SecBg() as Brush ?? Brushes.Transparent
            };
            _popOutWindows[widget.Type] = win;
            win.Closed += (_, __) => _popOutWindows.Remove(widget.Type);

            var dock = new DockPanel { Margin = new Thickness(8) };

            var refreshBtn = new Button
            {
                Content = new IconBlock { Icon = IconChar.ArrowsRotate, Width = 12, Height = 12 },
                Background = Brushes.Transparent, BorderThickness = new Thickness(0),
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 0, 0, 6), ToolTip = "Refresh", Cursor = Cursors.Hand
            };
            DockPanel.SetDock(refreshBtn, Dock.Top);
            dock.Children.Add(refreshBtn);
            dock.Children.Add(content);
            win.Content = dock;

            refreshBtn.Click += (_, __) =>
            {
                if (dock.Children.Count > 1) dock.Children.RemoveAt(dock.Children.Count - 1);
                var fresh = BuildWidgetContent(widget);
                if (fresh != null) dock.Children.Add(fresh);
            };

            win.Show();
        }

        // ── Content factory (single switch — no repetition) ───────────────────────
        private UIElement BuildWidgetContent(DashboardWidget widget) => widget.Type switch
        {
            WidgetType.ModuleStatus     => W_ModuleStatus(),
            WidgetType.RecentFindings   => W_RecentFindings(widget.Size),
            WidgetType.IDSAlerts        => W_IDSAlerts(),
            WidgetType.TrafficStats     => W_TrafficStats(),
            WidgetType.TopThreats       => W_TopThreats(),
            WidgetType.SecurityScore    => W_SecurityScore(),
            WidgetType.NetworkSpeed     => W_NetworkSpeed(),
            WidgetType.HostsList        => W_HostsList(widget.Size),
            WidgetType.ActivityChart    => W_ActivityChart(),
            WidgetType.VulnSummary      => W_VulnSummary(),
            WidgetType.QuickActions     => W_QuickActions(),
            WidgetType.SystemResources  => W_SystemResources(),
            WidgetType.OpenPorts        => W_OpenPorts(),
            WidgetType.AlertTrend       => W_AlertTrend(),
            WidgetType.HoneypotActivity => W_HoneypotActivity(),
            WidgetType.CVEExploit       => W_CVEExploit(),
            WidgetType.AssetChanges     => W_AssetChanges(),
            WidgetType.IdsRuleStats     => W_IdsRuleStats(),
            WidgetType.LiveTraffic      => W_LiveTraffic(),
            _                           => null
        };

        // =========================================================================
        // MODULE STATUS
        // =========================================================================
        private UIElement W_ModuleStatus()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(W_Header(IconChar.CircleDot, "Module Status", Color.FromRgb(33, 150, 243)));

            var modules = new[]
            {
                BuildModuleRow("Port Scanner",       "NetworkWired", GetPortScannerStatus()),
                BuildModuleRow("Network Discovery",  "Globe",        GetNetDiscoveryStatus()),
                BuildModuleRow("Traffic Analysis",   "Wifi",         GetTrafficStatus()),
                BuildModuleRow("IDS Engine",          "Shield",       GetIDSStatus()),
                BuildModuleRow("Vulnerability",       "Bug",          GetVulnStatus()),
                BuildModuleRow("Security Check",      "ShieldHalved", GetSecCheckStatus()),
            };

            foreach (var row in modules) sp.Children.Add(row);
            return sp;
        }

        private (string label, string status, Brush dot, string detail) GetPortScannerStatus()
        {
            var cnt = _stateService.RecentScanResults.Count(r => r.Type.Contains("Port", StringComparison.OrdinalIgnoreCase));
            return ("", cnt > 0 ? "Active" : "Idle", cnt > 0 ? GreenBrush : YellowBrush, $"{cnt} scans");
        }

        private (string label, string status, Brush dot, string detail) GetNetDiscoveryStatus()
        {
            var cnt = _stateService.NetworkScanResults.Count;
            return ("", cnt > 0 ? "Active" : "Idle", cnt > 0 ? GreenBrush : YellowBrush, $"{cnt} hosts");
        }

        private (string label, string status, Brush dot, string detail) GetTrafficStatus()
        {
            bool cap = false; long pkts = 0;
            try { cap = TrafficCaptureService.Instance.IsCapturing; pkts = TrafficCaptureService.Instance.Statistics.TotalPackets; } catch { }
            return ("", cap ? "Capturing" : "Idle", cap ? GreenBrush : YellowBrush, $"{pkts:N0} pkts");
        }

        private (string label, string status, Brush dot, string detail) GetIDSStatus()
        {
            bool running = false; int alerts = 0;
            try { running = IDSManager.Engine.IsRunning; alerts = IDSManager.Engine.Alerts.Count; } catch { }
            var dot = alerts > 0 ? RedBrush : (running ? GreenBrush : YellowBrush);
            return ("", running ? "Running" : "Stopped", dot, $"{alerts} alerts");
        }

        private (string label, string status, Brush dot, string detail) GetVulnStatus()
        {
            var cnt = _stateService.VulnerabilityScanResults.Count;
            return ("", cnt > 0 ? "Active" : "Idle", cnt > 0 ? YellowBrush : GreenBrush, $"{cnt} findings");
        }

        private (string label, string status, Brush dot, string detail) GetSecCheckStatus()
        {
            var cnt = _stateService.RecentScanResults.Count(r => r.Type.Contains("Security", StringComparison.OrdinalIgnoreCase));
            return ("", cnt > 0 ? "Done" : "Idle", cnt > 0 ? GreenBrush : YellowBrush, $"{cnt} checks");
        }

        private Border BuildModuleRow(string name, string iconName, (string label, string status, Brush dot, string detail) info)
        {
            var row = new Border
            {
                Background      = W_BgBrush(),
                CornerRadius    = new CornerRadius(6),
                Margin          = new Thickness(0, 0, 0, 5),
                Padding         = new Thickness(10, 7, 10, 7)
            };

            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            // Dot
            var dot = new Ellipse { Width = 8, Height = 8, Fill = info.dot, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
            Grid.SetColumn(dot, 0);
            g.Children.Add(dot);

            // Name
            var nameTb = new TextBlock { Text = name, FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(nameTb, 1);
            g.Children.Add(nameTb);

            // Status badge
            var statusColor = info.status == "Running" || info.status == "Active" || info.status == "Done" || info.status == "Capturing"
                ? new SolidColorBrush(Color.FromRgb(76, 175, 80))
                : (info.status == "Stopped" ? RedBrush : YellowBrush);
            var badge = W_Badge(info.status, statusColor, 9);
            badge.Margin = new Thickness(0, 0, 6, 0);
            Grid.SetColumn(badge, 2);
            g.Children.Add(badge);

            // Detail
            var detail = new TextBlock { Text = info.detail, FontSize = 9, Opacity = 0.55, Foreground = W_TextBrush(), VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(detail, 3);
            g.Children.Add(detail);

            row.Child = g;
            return row;
        }

        // =========================================================================
        // RECENT FINDINGS
        // =========================================================================
        private UIElement W_RecentFindings(WidgetSize size)
        {
            var sp = new StackPanel { Margin = new Thickness(16) };

            var allScans = _scanHistory.Values.SelectMany(v => v)
                .Concat(_stateService.RecentScanResults)
                .GroupBy(s => $"{s.Timestamp:yyyyMMddHHmmss}_{s.Type}_{s.Description}")
                .Select(g => g.First())
                .OrderByDescending(s => s.Timestamp)
                .ToList();

            int take = size == WidgetSize.Large ? 10 : 6;

            // Right-side count badge
            var countBadge = W_Badge($"{allScans.Count} total", new SolidColorBrush(Color.FromRgb(33, 150, 243)), 9);
            sp.Children.Add(W_Header(IconChar.ClipboardList, "Recent Findings", Color.FromRgb(255, 152, 0), countBadge));

            if (!allScans.Any())
            {
                sp.Children.Add(W_EmptyHint("No scan results yet — run a scan first"));
                return sp;
            }

            foreach (var s in allScans.Take(take))
            {
                var row = new Border
                {
                    Background      = W_BgBrush(),
                    CornerRadius    = new CornerRadius(6),
                    Margin          = new Thickness(0, 0, 0, 5),
                    Padding         = new Thickness(10, 7, 10, 7),
                    Cursor          = Cursors.Hand
                };

                var g = new Grid();
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                // Severity dot
                var dotColor = s.Status?.ToLower() switch
                {
                    "error"   => Color.FromRgb(244, 67, 54),
                    "warning" => Color.FromRgb(255, 193, 7),
                    "good"    => Color.FromRgb(76, 175, 80),
                    _         => Color.FromRgb(120, 120, 120)
                };
                var dot = new Ellipse { Width = 8, Height = 8, Fill = new SolidColorBrush(dotColor), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
                Grid.SetColumn(dot, 0);
                g.Children.Add(dot);

                // Type + description
                var inner = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                inner.Children.Add(new TextBlock { Text = s.Type ?? "Unknown", FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), TextTrimming = TextTrimming.CharacterEllipsis });
                inner.Children.Add(new TextBlock { Text = s.Description ?? "", FontSize = 9, Opacity = 0.6, Foreground = W_TextBrush(), TextTrimming = TextTrimming.CharacterEllipsis });
                Grid.SetColumn(inner, 1);
                g.Children.Add(inner);

                // Time
                var time = new TextBlock { Text = FormatRelativeTime(s.Timestamp), FontSize = 9, Opacity = 0.55, Foreground = W_TextBrush(), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(6, 0, 0, 0) };
                Grid.SetColumn(time, 2);
                g.Children.Add(time);

                // Status badge
                var statusBadge = W_Badge(s.Status ?? "–", new SolidColorBrush(dotColor), 9);
                statusBadge.Margin = new Thickness(5, 0, 0, 0);
                Grid.SetColumn(statusBadge, 3);
                g.Children.Add(statusBadge);

                row.Child = g;

                // Click to navigate
                var capture = s;
                row.MouseLeftButtonDown += (_, __) => HandleScanResultNavigation(capture);
                sp.Children.Add(row);
            }

            return sp;
        }

        // =========================================================================
        // IDS ALERTS
        // =========================================================================
        private UIElement W_IDSAlerts()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };

            List<Models.IDSAlert> alerts = new();
            int statCrit = 0, statHigh = 0, statMed = 0, statLow = 0;
            bool running = false;
            try
            {
                alerts  = IDSManager.Engine.Alerts.ToList();
                running = IDSManager.Engine.IsRunning;
                var stats = IDSManager.Engine.GetStats();
                statCrit = stats.CriticalAlerts; statHigh = stats.HighAlerts;
                statMed  = stats.MediumAlerts;   statLow  = stats.LowAlerts;
            }
            catch { }

            // Header with live indicator
            var runDot = new Ellipse { Width = 8, Height = 8, Fill = running ? GreenBrush : YellowBrush, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 4, 0) };
            var runLabel = new TextBlock { Text = running ? "Live" : "Stopped", FontSize = 10, Foreground = running ? GreenBrush : YellowBrush, VerticalAlignment = VerticalAlignment.Center };
            var livePanel = new StackPanel { Orientation = Orientation.Horizontal };
            livePanel.Children.Add(runDot);
            livePanel.Children.Add(runLabel);
            sp.Children.Add(W_Header(IconChar.TriangleExclamation, "IDS Alerts", Color.FromRgb(244, 67, 54), livePanel));

            // Severity summary strip
            var strip = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            strip.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            strip.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            strip.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            strip.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            void AddSevCell(int col, string label, int count, Color bg)
            {
                var cell = new Border { Background = new SolidColorBrush(Color.FromArgb(30, bg.R, bg.G, bg.B)), CornerRadius = new CornerRadius(6), Padding = new Thickness(4, 6, 4, 6), Margin = new Thickness(col == 0 ? 0 : 3, 0, 0, 0) };
                var inner = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
                inner.Children.Add(new TextBlock { Text = count.ToString(), FontSize = 18, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(bg), HorizontalAlignment = HorizontalAlignment.Center });
                inner.Children.Add(new TextBlock { Text = label, FontSize = 9, Foreground = new SolidColorBrush(bg), HorizontalAlignment = HorizontalAlignment.Center });
                cell.Child = inner;
                Grid.SetColumn(cell, col);
                strip.Children.Add(cell);
            }

            AddSevCell(0, "CRIT",   statCrit, Color.FromRgb(244, 67, 54));
            AddSevCell(1, "HIGH",   statHigh, Color.FromRgb(255, 109, 0));
            AddSevCell(2, "MED",    statMed,  Color.FromRgb(255, 193, 7));
            AddSevCell(3, "LOW",    statLow,  Color.FromRgb(76, 175, 80));
            sp.Children.Add(strip);

            if (!alerts.Any())
            {
                sp.Children.Add(W_EmptyHint("No IDS alerts — network looks clean"));
                return sp;
            }

            // Alert rows
            foreach (var a in alerts.OrderByDescending(x => x.Timestamp).Take(8))
            {
                var row = new Border
                {
                    Background   = W_BgBrush(),
                    CornerRadius = new CornerRadius(6),
                    Margin       = new Thickness(0, 0, 0, 4),
                    Padding      = new Thickness(9, 6, 9, 6)
                };

                var g = new Grid();
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var sevColor = a.SeverityText?.ToLower() switch
                {
                    "critical" => Color.FromRgb(244, 67, 54),
                    "high"     => Color.FromRgb(255, 109, 0),
                    "medium"   => Color.FromRgb(255, 193, 7),
                    _          => Color.FromRgb(76, 175, 80)
                };
                var sevBadge = W_Badge(a.SeverityText?.ToUpper() ?? "?", new SolidColorBrush(sevColor), 8);
                sevBadge.Margin = new Thickness(0, 0, 8, 0);
                Grid.SetColumn(sevBadge, 0);
                g.Children.Add(sevBadge);

                var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                info.Children.Add(new TextBlock { Text = a.AlertType ?? "Alert", FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), TextTrimming = TextTrimming.CharacterEllipsis });
                info.Children.Add(new TextBlock { Text = a.SourceIP ?? "", FontSize = 9, Opacity = 0.55, Foreground = W_TextBrush() });
                Grid.SetColumn(info, 1);
                g.Children.Add(info);

                var time = new TextBlock { Text = FormatRelativeTime(a.Timestamp), FontSize = 9, Opacity = 0.5, Foreground = W_TextBrush(), VerticalAlignment = VerticalAlignment.Center };
                Grid.SetColumn(time, 2);
                g.Children.Add(time);

                row.Child = g;
                sp.Children.Add(row);
            }

            return sp;
        }

        // =========================================================================
        // TRAFFIC STATS
        // =========================================================================
        private UIElement W_TrafficStats()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };

            long totalPkts = 0; bool capturing = false;
            Dictionary<string, long> protocols = new();
            try
            {
                totalPkts  = TrafficCaptureService.Instance.Statistics.TotalPackets;
                capturing  = TrafficCaptureService.Instance.IsCapturing;
                protocols  = TrafficCaptureService.Instance.Statistics.ProtocolPacketCounts ?? new Dictionary<string, long>();
            }
            catch { }

            var capIndicator = W_Badge(capturing ? "● Capturing" : "○ Idle",
                capturing ? new SolidColorBrush(Color.FromRgb(76, 175, 80)) : YellowBrush, 9);
            sp.Children.Add(W_Header(IconChar.Wifi, "Traffic Stats", Color.FromRgb(156, 39, 176), capIndicator));

            // Big numbers row
            var numGrid = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            numGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            numGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            void AddStatCell(int col, string value, string label, Color c)
            {
                var cell = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
                cell.Children.Add(new TextBlock { Text = value, FontSize = 22, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(c), HorizontalAlignment = HorizontalAlignment.Center });
                cell.Children.Add(new TextBlock { Text = label, FontSize = 9, Opacity = 0.6, Foreground = W_TextBrush(), HorizontalAlignment = HorizontalAlignment.Center });
                Grid.SetColumn(cell, col);
                numGrid.Children.Add(cell);
            }

            AddStatCell(0, totalPkts.ToString("N0"),   "Total Packets",   Color.FromRgb(156, 39, 176));
            AddStatCell(1, protocols.Count.ToString(),  "Protocols Seen",  Color.FromRgb(33, 150, 243));
            sp.Children.Add(numGrid);

            // Protocol mini-bars
            if (protocols.Any())
            {
                sp.Children.Add(new TextBlock { Text = "Protocol Mix", FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), Opacity = 0.7, Margin = new Thickness(0, 0, 0, 6) });
                var top = protocols.OrderByDescending(x => x.Value).Take(5).ToList();
                double maxVal = top.First().Value;
                var palette = new[] { Color.FromRgb(33,150,243), Color.FromRgb(76,175,80), Color.FromRgb(255,152,0), Color.FromRgb(244,67,54), Color.FromRgb(156,39,176) };
                int ci = 0;
                foreach (var kv in top)
                {
                    var c = palette[ci++ % palette.Length];
                    sp.Children.Add(W_MiniBar(kv.Key, kv.Value, maxVal, c));
                }
            }
            else
            {
                sp.Children.Add(W_EmptyHint("Start a capture to see protocol data"));
            }

            return sp;
        }

        // =========================================================================
        // TOP THREATS
        // =========================================================================
        private UIElement W_TopThreats()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(W_Header(IconChar.SkullCrossbones, "Top Threats", Color.FromRgb(244, 67, 54)));

            List<Models.IDSAlert> alerts = new();
            try { alerts = IDSManager.Engine.Alerts.ToList(); } catch { }

            var threats = alerts
                .GroupBy(a => a.AttackCategory ?? a.AlertType ?? "Unknown")
                .Select(g => (cat: g.Key, count: g.Count(), severity: g.Max(x => x.Severity)))
                .OrderByDescending(x => x.count)
                .Take(7)
                .ToList();

            if (!threats.Any())
            {
                try
                {
                    var trafficThreats = TrafficCaptureService.Instance.Alerts
                        .Where(a => a.Severity != ThreatLevel.None)
                        .GroupBy(a => a.Category ?? "Traffic")
                        .Select(g => (cat: g.Key, count: g.Count()))
                        .OrderByDescending(x => x.count)
                        .Take(7)
                        .ToList();
                    if (trafficThreats.Any())
                    {
                        double max = trafficThreats.First().count;
                        foreach (var t in trafficThreats)
                            sp.Children.Add(W_MiniBar(t.cat, t.count, max, Color.FromRgb(244, 67, 54)));
                        return sp;
                    }
                }
                catch { }

                sp.Children.Add(W_EmptyHint("No threats detected yet — great news!"));
                return sp;
            }

            double maxCount = threats.First().count;
            var palette = new[]
            {
                Color.FromRgb(244, 67, 54),
                Color.FromRgb(255, 109, 0),
                Color.FromRgb(255, 193, 7),
                Color.FromRgb(76, 175, 80),
                Color.FromRgb(33, 150, 243),
                Color.FromRgb(156, 39, 176),
                Color.FromRgb(0, 188, 212)
            };
            int idx = 0;
            foreach (var t in threats)
                sp.Children.Add(W_MiniBar(t.cat, t.count, maxCount, palette[idx++ % palette.Length]));

            return sp;
        }

        // =========================================================================
        // SECURITY SCORE
        // =========================================================================
        private UIElement W_SecurityScore()
        {
            var sp = new StackPanel { Margin = new Thickness(16), HorizontalAlignment = HorizontalAlignment.Center };
            sp.Children.Add(W_Header(IconChar.ShieldHalved, "Security Score", Color.FromRgb(0, 188, 212)));

            // Pull score from recent scan results
            var lastCheck = _stateService.RecentScanResults
                .Where(r => r.Type.Contains("Security Check", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(r => r.Timestamp)
                .FirstOrDefault();

            string scoreStr = "--", riskStr = "Not Scanned", emoji = "😐";
            Color scoreColor = Color.FromRgb(120, 120, 120);

            if (lastCheck != null)
            {
                var scoreLine = lastCheck.Details?.FirstOrDefault(d => d.StartsWith("Score:"));
                var riskLine  = lastCheck.Details?.FirstOrDefault(d => d.StartsWith("Risk Level:"));
                if (scoreLine != null && double.TryParse(scoreLine.Replace("Score:", "").Replace("/100", "").Trim(), out double score))
                {
                    scoreStr = $"{score:F0}";
                    if (score >= 90) { scoreColor = Color.FromRgb(76, 175, 80); emoji = "🥳"; riskStr = "Excellent"; }
                    else if (score >= 80) { scoreColor = Color.FromRgb(102, 187, 106); emoji = "😎"; riskStr = "Very Good"; }
                    else if (score >= 70) { scoreColor = Color.FromRgb(129, 199, 132); emoji = "😊"; riskStr = "Good"; }
                    else if (score >= 60) { scoreColor = Color.FromRgb(255, 193, 7); emoji = "🤔"; riskStr = "Moderate"; }
                    else if (score >= 40) { scoreColor = Color.FromRgb(255, 152, 0); emoji = "😰"; riskStr = "High Risk"; }
                    else { scoreColor = Color.FromRgb(244, 67, 54); emoji = "😱"; riskStr = "Critical"; }
                }
                if (riskLine != null) riskStr = riskLine.Replace("Risk Level:", "").Trim();
            }

            // Score ring placeholder (colored circle background)
            var ring = new Border
            {
                Width = 80, Height = 80,
                CornerRadius = new CornerRadius(40),
                Background = new SolidColorBrush(Color.FromArgb(30, scoreColor.R, scoreColor.G, scoreColor.B)),
                BorderBrush = new SolidColorBrush(scoreColor),
                BorderThickness = new Thickness(3),
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 6, 0, 6)
            };
            var ringContent = new StackPanel { VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center };
            ringContent.Children.Add(new TextBlock { Text = scoreStr, FontSize = 24, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(scoreColor), HorizontalAlignment = HorizontalAlignment.Center });
            ring.Child = ringContent;
            sp.Children.Add(ring);

            sp.Children.Add(new TextBlock { Text = $"{emoji} {riskStr}", FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(scoreColor), HorizontalAlignment = HorizontalAlignment.Center });

            if (lastCheck != null)
                sp.Children.Add(new TextBlock { Text = $"Last: {FormatRelativeTime(lastCheck.Timestamp)}", FontSize = 9, Opacity = 0.5, Foreground = W_TextBrush(), HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 4, 0, 8) });
            else
                sp.Children.Add(new TextBlock { Text = "Click ▶ Run Check to scan", FontSize = 9, Opacity = 0.5, Foreground = W_TextBrush(), HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 4, 0, 8) });

            var runBtn = new Button
            {
                Content = "▶  Run Check",
                Height = 28, Padding = new Thickness(16, 0, 16, 0),
                Background = new SolidColorBrush(Color.FromRgb(0, 188, 212)),
                Foreground = Brushes.White, BorderThickness = new Thickness(0),
                FontSize = 11, FontWeight = FontWeights.SemiBold,
                Cursor = Cursors.Hand,
                HorizontalAlignment = HorizontalAlignment.Center
            };
            runBtn.Click += SecurityCheckButton_Click;
            sp.Children.Add(runBtn);

            return sp;
        }

        // =========================================================================
        // NETWORK SPEED
        // =========================================================================
        private UIElement W_NetworkSpeed()
        {
            var sp = new StackPanel { Margin = new Thickness(16), HorizontalAlignment = HorizontalAlignment.Center };
            sp.Children.Add(W_Header(IconChar.Gauge, "Network Speed", Color.FromRgb(0, 188, 212)));

            var lastSpeed = _stateService.RecentScanResults
                .Where(r => r.Type.Contains("Speed", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(r => r.Timestamp)
                .FirstOrDefault();

            string speedStr = "--", qualityStr = "Not Tested";
            Color speedColor = Color.FromRgb(120, 120, 120);

            if (lastSpeed != null)
            {
                var speedLine = lastSpeed.Details?.FirstOrDefault(d => d.StartsWith("Speed:"));
                if (speedLine != null)
                {
                    speedStr   = speedLine.Replace("Speed:", "").Trim();
                    qualityStr = lastSpeed.Status == "Good" ? "Excellent" : lastSpeed.Status == "Warning" ? "Moderate" : "Poor";
                    speedColor = lastSpeed.Status == "Good" ? Color.FromRgb(76, 175, 80)
                               : lastSpeed.Status == "Warning" ? Color.FromRgb(255, 193, 7)
                               : Color.FromRgb(244, 67, 54);
                }
            }

            sp.Children.Add(new TextBlock { Text = speedStr, FontSize = 28, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(speedColor), HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 8, 0, 0) });
            sp.Children.Add(new TextBlock { Text = qualityStr, FontSize = 11, Foreground = new SolidColorBrush(speedColor), HorizontalAlignment = HorizontalAlignment.Center });

            var testBtn = new Button
            {
                Content = "Test Now",
                Height = 26, Padding = new Thickness(14, 0, 14, 0),
                Background = new SolidColorBrush(Color.FromRgb(0, 150, 180)),
                Foreground = Brushes.White, BorderThickness = new Thickness(0),
                FontSize = 11, Cursor = Cursors.Hand,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 8, 0, 0)
            };
            testBtn.Click += TestSpeedButton_Click;
            sp.Children.Add(testBtn);

            return sp;
        }

        // =========================================================================
        // HOSTS LIST
        // =========================================================================
        private UIElement W_HostsList(WidgetSize size)
        {
            var sp = new StackPanel { Margin = new Thickness(16) };
            var hosts = _stateService.NetworkScanResults.ToList();
            var countBadge = W_Badge($"{hosts.Count} hosts", new SolidColorBrush(Color.FromRgb(76, 175, 80)), 9);
            sp.Children.Add(W_Header(IconChar.Desktop, "Discovered Hosts", Color.FromRgb(76, 175, 80), countBadge));

            if (!hosts.Any())
            {
                sp.Children.Add(W_EmptyHint("No hosts found — run Network Discovery"));
                return sp;
            }

            int take = size == WidgetSize.Large ? 12 : 7;
            foreach (var h in hosts.Take(take))
            {
                var row = new Border
                {
                    Background   = W_BgBrush(),
                    CornerRadius = new CornerRadius(6),
                    Margin       = new Thickness(0, 0, 0, 4),
                    Padding      = new Thickness(10, 7, 10, 7)
                };

                var g = new Grid();
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var isOnline = h.IsOnline || h.Status?.ToLower() == "online";
                var dot = new Ellipse { Width = 8, Height = 8, Fill = isOnline ? GreenBrush : YellowBrush, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
                Grid.SetColumn(dot, 0);
                g.Children.Add(dot);

                var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                info.Children.Add(new TextBlock { Text = h.IPAddress ?? "Unknown IP", FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush() });
                if (!string.IsNullOrWhiteSpace(h.Hostname) && h.Hostname != h.IPAddress)
                    info.Children.Add(new TextBlock { Text = h.Hostname, FontSize = 9, Opacity = 0.55, Foreground = W_TextBrush() });
                Grid.SetColumn(info, 1);
                g.Children.Add(info);

                if (!string.IsNullOrWhiteSpace(h.OS) || !string.IsNullOrWhiteSpace(h.DeviceType))
                {
                    var tag = W_Badge(h.OS ?? h.DeviceType ?? "Unknown", new SolidColorBrush(Color.FromRgb(80, 80, 100)), 8);
                    Grid.SetColumn(tag, 2);
                    g.Children.Add(tag);
                }

                row.Child = g;
                sp.Children.Add(row);
            }

            if (hosts.Count > take)
                sp.Children.Add(new TextBlock { Text = $"+ {hosts.Count - take} more", FontSize = 9, Opacity = 0.5, Foreground = W_TextBrush(), Margin = new Thickness(0, 4, 0, 0) });

            return sp;
        }

        // =========================================================================
        // ACTIVITY CHART (7-day bar chart)
        // =========================================================================
        private UIElement W_ActivityChart()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(W_Header(IconChar.ChartBar, "Activity — 7 Days", Color.FromRgb(33, 150, 243)));

            var canvas = new System.Windows.Controls.Canvas { Height = 160 };
            canvas.Loaded       += (_, __) => DrawWidget7DayChart(canvas);
            canvas.SizeChanged  += (_, __) => DrawWidget7DayChart(canvas);
            sp.Children.Add(canvas);

            return sp;
        }

        private void DrawWidget7DayChart(System.Windows.Controls.Canvas canvas)
        {
            var data = new List<(string label, double value, Color barColor)>();
            for (int i = 6; i >= 0; i--)
            {
                var date  = DateTime.Today.AddDays(-i);
                var count = _stateService.RecentScanResults.Count(r => r.Timestamp.Date == date)
                          + (_scanHistory.ContainsKey(date) ? _scanHistory[date].Count : 0);
                data.Add((date.ToString("ddd"), count, Color.FromRgb(33, 150, 243)));
            }
            DrawDayBarChart(canvas, data);
        }

        // =========================================================================
        // VULNERABILITY SUMMARY
        // =========================================================================
        private UIElement W_VulnSummary()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(W_Header(IconChar.Bug, "Vulnerability Summary", Color.FromRgb(156, 39, 176)));

            var allScans = _scanHistory.Values.SelectMany(v => v)
                .Concat(_stateService.RecentScanResults)
                .Where(r => r.Type.Contains("Vuln", StringComparison.OrdinalIgnoreCase) ||
                            r.Type.Contains("CVE",  StringComparison.OrdinalIgnoreCase))
                .ToList();

            // Classify by status
            int critical = allScans.Count(r => r.Status == "Error" && r.Details?.Any(d => d.Contains("Critical", StringComparison.OrdinalIgnoreCase)) == true);
            int high     = allScans.Count(r => r.Status == "Error") - critical;
            int medium   = allScans.Count(r => r.Status == "Warning");
            int low      = allScans.Count(r => r.Status == "Good");
            // Also count VulnerabilityScanResults
            int portVulns = _stateService.VulnerabilityScanResults.Count(r => r.IsOpen);

            var g = new Grid { Margin = new Thickness(0, 4, 0, 10) };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            void AddVulnCell(int col, string label, int count, Color c)
            {
                var cell = new Border { Background = new SolidColorBrush(Color.FromArgb(25, c.R, c.G, c.B)), CornerRadius = new CornerRadius(6), Padding = new Thickness(4, 8, 4, 8), Margin = new Thickness(col == 0 ? 0 : 3, 0, 0, 0) };
                var inner = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
                inner.Children.Add(new TextBlock { Text = count.ToString(), FontSize = 20, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(c), HorizontalAlignment = HorizontalAlignment.Center });
                inner.Children.Add(new TextBlock { Text = label, FontSize = 8, Foreground = new SolidColorBrush(c), HorizontalAlignment = HorizontalAlignment.Center });
                cell.Child = inner;
                Grid.SetColumn(cell, col);
                g.Children.Add(cell);
            }

            AddVulnCell(0, "Critical", critical, Color.FromRgb(244, 67, 54));
            AddVulnCell(1, "High",     high,     Color.FromRgb(255, 109, 0));
            AddVulnCell(2, "Medium",   medium,   Color.FromRgb(255, 193, 7));
            AddVulnCell(3, "Low",      low,      Color.FromRgb(76, 175, 80));
            sp.Children.Add(g);

            int total = critical + high + medium + low + portVulns;
            sp.Children.Add(new TextBlock { Text = $"Total: {total}  •  Open ports with vulns: {portVulns}", FontSize = 9, Opacity = 0.55, Foreground = W_TextBrush() });

            return sp;
        }

        // =========================================================================
        // QUICK ACTIONS
        // =========================================================================
        private UIElement W_QuickActions()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(W_Header(IconChar.BoltLightning, "Quick Actions", Color.FromRgb(255, 152, 0)));

            var actions = new[]
            {
                (icon: IconChar.MagnifyingGlass, color: Color.FromRgb(33,150,243),  label: "Port Scan",      page: "Port Scanner"),
                (icon: IconChar.Sitemap,          color: Color.FromRgb(76,175,80),   label: "Network Scan",   page: "Network Discovery"),
                (icon: IconChar.ChartLine,        color: Color.FromRgb(156,39,176),  label: "Capture",        page: "Traffic Analysis"),
                (icon: IconChar.Shield,           color: Color.FromRgb(244,67,54),   label: "Run IDS",        page: "IDS"),
                (icon: IconChar.Bug,              color: Color.FromRgb(255,152,0),   label: "Vulnerability",  page: "Vulnerability"),
                (icon: IconChar.ShieldHalved,     color: Color.FromRgb(0,188,212),   label: "Sec Check",      page: (string)null),
            };

            var wrap = new WrapPanel { Margin = new Thickness(0, 4, 0, 0) };
            foreach (var a in actions)
            {
                var accentBrush = new SolidColorBrush(a.color);

                var btn = new Button
                {
                    Width = 98, Height = 66,
                    Background = W_BgBrush(),
                    BorderBrush = W_Border(),
                    BorderThickness = new Thickness(1),
                    Cursor = Cursors.Hand,
                    Margin = new Thickness(0, 0, 6, 6)
                };

                // Icon badge
                var iconBorder = new Border
                {
                    Width = 32, Height = 32,
                    CornerRadius = new CornerRadius(8),
                    Background = new SolidColorBrush(Color.FromArgb(30, a.color.R, a.color.G, a.color.B)),
                    Margin = new Thickness(0, 0, 0, 4),
                    Child = new IconBlock { Icon = a.icon, Foreground = accentBrush, Width = 14, Height = 14 },
                    HorizontalAlignment = HorizontalAlignment.Center
                };

                var inner = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                inner.Children.Add(iconBorder);
                inner.Children.Add(new TextBlock { Text = a.label, FontSize = 9, Foreground = W_TextBrush(), HorizontalAlignment = HorizontalAlignment.Center });
                btn.Content = inner;

                var capture = a;
                btn.Click += (_, __) =>
                {
                    if (capture.page == null) { SecurityCheckButton_Click(btn, new RoutedEventArgs()); return; }
                    var mainWin = Application.Current.MainWindow as MainWindow;
                    mainWin?.NavigateToPageWithState(capture.page, null);
                };

                btn.MouseEnter += (_, __) =>
                {
                    btn.Background = new SolidColorBrush(Color.FromArgb(20, capture.color.R, capture.color.G, capture.color.B));
                    btn.BorderBrush = new SolidColorBrush(capture.color);
                };
                btn.MouseLeave += (_, __) =>
                {
                    btn.Background = W_BgBrush();
                    btn.BorderBrush = W_Border();
                };

                wrap.Children.Add(btn);
            }

            sp.Children.Add(wrap);
            return sp;
        }

        // =========================================================================
        // SYSTEM RESOURCES
        // =========================================================================
        private UIElement W_SystemResources()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(W_Header(IconChar.Server, "System Resources", Color.FromRgb(0, 188, 212)));

            // App memory
            long memMb = 0;
            try { memMb = System.Diagnostics.Process.GetCurrentProcess().WorkingSet64 / 1024 / 1024; } catch { }
            sp.Children.Add(new TextBlock { Text = "Application Memory", FontSize = 10, Opacity = 0.6, Foreground = W_TextBrush(), Margin = new Thickness(0, 0, 0, 3) });
            sp.Children.Add(W_ResourceBar($"{memMb} MB", Math.Min((double)memMb / 1024.0, 1.0), Color.FromRgb(33, 150, 243)));

            // Drive space
            try
            {
                var drives = DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed).ToList();
                foreach (var drive in drives.Take(2))
                {
                    double usedFrac = 1.0 - ((double)drive.AvailableFreeSpace / drive.TotalSize);
                    long freeGb = drive.AvailableFreeSpace / 1024 / 1024 / 1024;
                    var dColor = usedFrac > 0.9 ? Color.FromRgb(244, 67, 54) : usedFrac > 0.7 ? Color.FromRgb(255, 193, 7) : Color.FromRgb(76, 175, 80);
                    sp.Children.Add(new TextBlock { Text = $"{drive.Name} Drive", FontSize = 10, Opacity = 0.6, Foreground = W_TextBrush(), Margin = new Thickness(0, 6, 0, 3) });
                    sp.Children.Add(W_ResourceBar($"{freeGb} GB free", usedFrac, dColor));
                }
            }
            catch { }

            // IDS status
            sp.Children.Add(new TextBlock { Text = "IDS Engine", FontSize = 10, Opacity = 0.6, Foreground = W_TextBrush(), Margin = new Thickness(0, 6, 0, 3) });
            bool idsOn = false; try { idsOn = IDSManager.Engine.IsRunning; } catch { }
            var idsBadge = W_Badge(idsOn ? "● Running" : "○ Stopped", idsOn ? GreenBrush : YellowBrush, 10);
            sp.Children.Add(idsBadge);

            return sp;
        }

        private Border W_ResourceBar(string label, double fraction, Color barColor)
        {
            var outer = new Border { Margin = new Thickness(0, 0, 0, 0) };
            var g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var track = new Border { Height = 6, Background = new SolidColorBrush(Color.FromArgb(30, barColor.R, barColor.G, barColor.B)), CornerRadius = new CornerRadius(3) };
            var fill  = new Border { Height = 6, Background = new SolidColorBrush(barColor), CornerRadius = new CornerRadius(3), HorizontalAlignment = HorizontalAlignment.Left };
            fill.Loaded += (_, __) =>
            {
                fill.Width = track.ActualWidth > 0 ? track.ActualWidth * fraction : 0;
            };
            track.SizeChanged += (_, e) => fill.Width = e.NewSize.Width * fraction;

            var overlay = new Grid();
            overlay.Children.Add(track);
            overlay.Children.Add(fill);
            Grid.SetRow(overlay, 0);
            g.Children.Add(overlay);

            var lbl = new TextBlock { Text = label, FontSize = 9, Opacity = 0.55, Foreground = W_TextBrush(), Margin = new Thickness(0, 2, 0, 0) };
            Grid.SetRow(lbl, 1);
            g.Children.Add(lbl);

            outer.Child = g;
            return outer;
        }

        // =========================================================================
        // OPEN PORTS
        // =========================================================================
        private UIElement W_OpenPorts()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(W_Header(IconChar.NetworkWired, "Open Ports", Color.FromRgb(33, 150, 243)));

            // Aggregate open ports from VulnerabilityScanResults and RecentScanResults details
            var portGroups = new Dictionary<int, (string service, int count)>();

            try
            {
                foreach (var p in _stateService.VulnerabilityScanResults.Where(r => r.IsOpen))
                {
                    if (!portGroups.ContainsKey(p.Port))
                        portGroups[p.Port] = (p.Service ?? "unknown", 0);
                    portGroups[p.Port] = (portGroups[p.Port].service, portGroups[p.Port].count + 1);
                }
            }
            catch { }

            // Also extract from scan result details strings
            var allScans = _scanHistory.Values.SelectMany(v => v)
                .Concat(_stateService.RecentScanResults)
                .Where(r => r.Type.Contains("Port", StringComparison.OrdinalIgnoreCase))
                .ToList();

            foreach (var s in allScans)
            {
                foreach (var d in s.Details ?? new System.Collections.Generic.List<string>())
                {
                    if (d.Contains("Open Port", StringComparison.OrdinalIgnoreCase))
                    {
                        // Try to extract port number from string like "Open Port: 80 (HTTP)"
                        var parts = d.Split(new[] { ':', ' ', '(', ')' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var part in parts)
                        {
                            if (int.TryParse(part, out int port) && port > 0 && port < 65536)
                            {
                                if (!portGroups.ContainsKey(port)) portGroups[port] = ("", 0);
                                portGroups[port] = (portGroups[port].service, portGroups[port].count + 1);
                                break;
                            }
                        }
                    }
                }
            }

            if (!portGroups.Any())
            {
                sp.Children.Add(W_EmptyHint("No open ports found — run a port scan"));
                return sp;
            }

            var wellKnown = new Dictionary<int, string> { {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},{80,"HTTP"},{110,"POP3"},{143,"IMAP"},{443,"HTTPS"},{445,"SMB"},{3306,"MySQL"},{3389,"RDP"},{5900,"VNC"},{8080,"HTTP-Alt"} };
            var sorted = portGroups.OrderByDescending(x => x.Value.count).Take(8).ToList();
            double maxCount = sorted.Any() ? sorted.First().Value.count : 1;

            foreach (var kv in sorted)
            {
                var svc = !string.IsNullOrWhiteSpace(kv.Value.service) ? kv.Value.service
                        : wellKnown.TryGetValue(kv.Key, out var wk) ? wk : "unknown";
                var label = $":{kv.Key}  {svc}";
                sp.Children.Add(W_MiniBar(label, kv.Value.count, maxCount, Color.FromRgb(33, 150, 243)));
            }

            return sp;
        }

        // =========================================================================
        // ALERT TREND (24h hourly)
        // =========================================================================
        private UIElement W_AlertTrend()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(W_Header(IconChar.ChartLine, "Alert Trend — 24h", Color.FromRgb(244, 67, 54)));

            var canvas = new System.Windows.Controls.Canvas { Height = 140 };

            List<Models.IDSAlert> alerts = new();
            try { alerts = IDSManager.Engine.Alerts.ToList(); } catch { }

            canvas.Loaded += (_, __) => DrawAlertTrendChart(canvas, alerts);
            canvas.SizeChanged += (_, __) => DrawAlertTrendChart(canvas, alerts);
            sp.Children.Add(canvas);

            int total = alerts.Count(a => a.Timestamp >= DateTime.Now.AddHours(-24));
            sp.Children.Add(new TextBlock { Text = $"{total} alerts in last 24h", FontSize = 9, Opacity = 0.55, Foreground = W_TextBrush(), Margin = new Thickness(0, 4, 0, 0) });

            return sp;
        }

        private void DrawAlertTrendChart(System.Windows.Controls.Canvas canvas, List<Models.IDSAlert> alerts)
        {
            var data = new List<(string label, double value, Color barColor)>();
            for (int i = 22; i >= 0; i -= 2)
            {
                var from  = DateTime.Now.AddHours(-i - 2);
                var to    = DateTime.Now.AddHours(-i);
                var count = alerts.Count(a => a.Timestamp >= from && a.Timestamp < to);
                var label = to.ToString("HH") + "h";
                var c = count == 0 ? Color.FromRgb(60, 60, 80) : Color.FromRgb(244, 67, 54);
                data.Add((label, count, c));
            }
            DrawDayBarChart(canvas, data);
        }

        // =========================================================================
        // HONEYPOT ACTIVITY
        // =========================================================================
        private UIElement W_HoneypotActivity()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(W_Header(IconChar.Spider, "Honeypot Activity", Color.FromRgb(233, 30, 99)));

            List<Models.IDSAlert> alerts = new();
            try { alerts = IDSManager.Engine.Alerts.ToList(); } catch { }

            var honeypotAlerts = alerts
                .Where(a => !string.IsNullOrWhiteSpace(a.HoneypotName))
                .ToList();

            if (!honeypotAlerts.Any())
            {
                // Fall back: show top attacking source IPs from all IDS alerts
                var topSources = alerts
                    .GroupBy(a => a.SourceIP ?? "Unknown")
                    .Select(g => (ip: g.Key, count: g.Count()))
                    .OrderByDescending(x => x.count).Take(5).ToList();

                if (!topSources.Any())
                {
                    sp.Children.Add(W_EmptyHint("No honeypot alerts yet — start IDS and deploy honeypots"));
                    return sp;
                }

                sp.Children.Add(new TextBlock { Text = "Top Attacking Sources", FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), Opacity = 0.7, Margin = new Thickness(0, 0, 0, 6) });
                double maxC = topSources.First().count;
                foreach (var s in topSources)
                    sp.Children.Add(W_MiniBar(s.ip, s.count, maxC, Color.FromRgb(233, 30, 99)));
                return sp;
            }

            // Summary strip
            var byHoneypot = honeypotAlerts
                .GroupBy(a => a.HoneypotName)
                .Select(g => (
                    name:  g.Key,
                    count: g.Count(),
                    last:  g.Max(x => x.Timestamp),
                    crit:  g.Count(x => x.SeverityText?.ToLower() == "critical" || x.SeverityText?.ToLower() == "high")))
                .OrderByDescending(x => x.count)
                .Take(6)
                .ToList();

            var numGrid = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            numGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            numGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            void AddStat(int col, string val, string lbl, Color c)
            {
                var cell = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
                cell.Children.Add(new TextBlock { Text = val, FontSize = 22, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(c), HorizontalAlignment = HorizontalAlignment.Center });
                cell.Children.Add(new TextBlock { Text = lbl, FontSize = 9, Opacity = 0.6, Foreground = W_TextBrush(), HorizontalAlignment = HorizontalAlignment.Center });
                Grid.SetColumn(cell, col);
                numGrid.Children.Add(cell);
            }
            AddStat(0, byHoneypot.Count.ToString(), "Traps Hit",    Color.FromRgb(233, 30, 99));
            AddStat(1, honeypotAlerts.Count.ToString(), "Total Hits", Color.FromRgb(244, 67, 54));
            sp.Children.Add(numGrid);

            foreach (var h in byHoneypot)
            {
                var row = new Border { Background = W_BgBrush(), CornerRadius = new CornerRadius(6), Margin = new Thickness(0, 0, 0, 4), Padding = new Thickness(10, 7, 10, 7) };
                var g = new Grid();
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                info.Children.Add(new TextBlock { Text = h.name, FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), TextTrimming = TextTrimming.CharacterEllipsis });
                info.Children.Add(new TextBlock { Text = FormatRelativeTime(h.last), FontSize = 9, Opacity = 0.55, Foreground = W_TextBrush() });
                Grid.SetColumn(info, 0);
                g.Children.Add(info);

                if (h.crit > 0)
                {
                    var critBadge = W_Badge($"⚠ {h.crit}", RedBrush, 8);
                    critBadge.Margin = new Thickness(0, 0, 5, 0);
                    Grid.SetColumn(critBadge, 1);
                    g.Children.Add(critBadge);
                }

                var cntBadge = W_Badge($"{h.count} hits", new SolidColorBrush(Color.FromRgb(233, 30, 99)), 9);
                Grid.SetColumn(cntBadge, 2);
                g.Children.Add(cntBadge);

                row.Child = g;
                sp.Children.Add(row);
            }

            return sp;
        }

        // =========================================================================
        // CVE EXPLOITS
        // =========================================================================
        private UIElement W_CVEExploit()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(W_Header(IconChar.Bomb, "CVE Exploits", Color.FromRgb(244, 67, 54)));

            var vulns = _stateService.VulnerabilityScanResults
                .Where(r => r.IsOpen && r.CveFindings?.Count > 0)
                .ToList();

            int totalCves = vulns.Sum(r => r.CveFindings.Count);
            if (totalCves == 0)
            {
                sp.Children.Add(W_EmptyHint("No CVEs found — run a port scan then use 'Check CVEs'"));
                return sp;
            }

            int critical = vulns.Sum(r => r.CveFindings.Count(c => c.Severity == "Critical"));
            int high     = vulns.Sum(r => r.CveFindings.Count(c => c.Severity == "High"));
            int medium   = vulns.Sum(r => r.CveFindings.Count(c => c.Severity == "Medium"));
            int low      = vulns.Sum(r => r.CveFindings.Count(c => c.Severity != "Critical" && c.Severity != "High" && c.Severity != "Medium"));

            // Severity strip
            var sevGrid = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            sevGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            sevGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            sevGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            sevGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            void AddCell(int col, string lbl, int cnt, Color c)
            {
                var cell = new Border { Background = new SolidColorBrush(Color.FromArgb(30, c.R, c.G, c.B)), CornerRadius = new CornerRadius(6), Padding = new Thickness(4, 6, 4, 6), Margin = new Thickness(col == 0 ? 0 : 3, 0, 0, 0) };
                var inner = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
                inner.Children.Add(new TextBlock { Text = cnt.ToString(), FontSize = 18, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(c), HorizontalAlignment = HorizontalAlignment.Center });
                inner.Children.Add(new TextBlock { Text = lbl, FontSize = 9, Foreground = new SolidColorBrush(c), HorizontalAlignment = HorizontalAlignment.Center });
                cell.Child = inner;
                Grid.SetColumn(cell, col);
                sevGrid.Children.Add(cell);
            }
            AddCell(0, "CRIT", critical, Color.FromRgb(244,  67, 54));
            AddCell(1, "HIGH", high,     Color.FromRgb(255, 109,  0));
            AddCell(2, "MED",  medium,   Color.FromRgb(255, 193,  7));
            AddCell(3, "LOW",  low,      Color.FromRgb( 76, 175, 80));
            sp.Children.Add(sevGrid);

            sp.Children.Add(new TextBlock { Text = "Top CVEs by CVSS", FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), Opacity = 0.7, Margin = new Thickness(0, 0, 0, 6) });

            var topCves = vulns
                .SelectMany(r => r.CveFindings.Select(c => (cve: c, port: r.Port, svc: r.Service ?? "")))
                .OrderByDescending(x => x.cve.Cvss)
                .Take(6)
                .ToList();

            foreach (var (cve, port, svc) in topCves)
            {
                var sevColor = cve.Severity switch
                {
                    "Critical" => Color.FromRgb(244,  67, 54),
                    "High"     => Color.FromRgb(255, 109,  0),
                    "Medium"   => Color.FromRgb(255, 193,  7),
                    _          => Color.FromRgb( 76, 175, 80)
                };

                var row = new Border { Background = W_BgBrush(), CornerRadius = new CornerRadius(6), Margin = new Thickness(0, 0, 0, 4), Padding = new Thickness(10, 7, 10, 7) };
                var g = new Grid();
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var inner = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                inner.Children.Add(new TextBlock { Text = cve.CveId, FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(sevColor), TextTrimming = TextTrimming.CharacterEllipsis });
                inner.Children.Add(new TextBlock { Text = $":{port} {svc}  {cve.CvssText}", FontSize = 9, Opacity = 0.6, Foreground = W_TextBrush() });
                Grid.SetColumn(inner, 0);
                g.Children.Add(inner);

                var badge = W_Badge(cve.Severity ?? "Unknown", new SolidColorBrush(sevColor), 8);
                Grid.SetColumn(badge, 1);
                g.Children.Add(badge);

                row.Child = g;
                sp.Children.Add(row);
            }

            return sp;
        }

        // =========================================================================
        // ASSET CHANGES
        // =========================================================================
        private UIElement W_AssetChanges()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };

            var assets = AssetInventoryService.Instance.Assets;
            var countBadge = W_Badge($"{assets.Count} assets", new SolidColorBrush(Color.FromRgb(0, 188, 212)), 9);
            sp.Children.Add(W_Header(IconChar.ArrowsRotate, "Asset Changes", Color.FromRgb(0, 188, 212), countBadge));

            if (!assets.Any())
            {
                sp.Children.Add(W_EmptyHint("No assets tracked — run Network Discovery first"));
                return sp;
            }

            // Summary strip
            int online  = assets.Count(a => a.IsOnline);
            int offline = assets.Count - online;
            var sumGrid = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            sumGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            sumGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            void AddSumCell(int col, string val, string lbl, Color c)
            {
                var cell = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
                cell.Children.Add(new TextBlock { Text = val, FontSize = 22, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(c), HorizontalAlignment = HorizontalAlignment.Center });
                cell.Children.Add(new TextBlock { Text = lbl, FontSize = 9, Opacity = 0.6, Foreground = W_TextBrush(), HorizontalAlignment = HorizontalAlignment.Center });
                Grid.SetColumn(cell, col);
                sumGrid.Children.Add(cell);
            }
            AddSumCell(0, online.ToString(),  "Online",  Color.FromRgb( 76, 175, 80));
            AddSumCell(1, offline.ToString(), "Offline", Color.FromRgb(120, 120, 120));
            sp.Children.Add(sumGrid);

            // Recent events — prefer last 24h, fall back to latest available
            var cutoff = DateTime.Now.AddHours(-24);
            var recentEvents = assets
                .SelectMany(a => a.History.Select(e => (asset: a, ev: e)))
                .Where(x => x.ev.Timestamp >= cutoff)
                .OrderByDescending(x => x.ev.Timestamp)
                .Take(8).ToList();

            if (!recentEvents.Any())
                recentEvents = assets
                    .SelectMany(a => a.History.Select(e => (asset: a, ev: e)))
                    .OrderByDescending(x => x.ev.Timestamp)
                    .Take(6).ToList();

            if (!recentEvents.Any())
            {
                sp.Children.Add(W_EmptyHint("No asset history yet — scan again to start tracking changes"));
                return sp;
            }

            sp.Children.Add(new TextBlock { Text = "Recent Events", FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), Opacity = 0.7, Margin = new Thickness(0, 0, 0, 6) });

            foreach (var (asset, ev) in recentEvents)
            {
                var (dotBrush, _) = ev.EventType switch
                {
                    "FirstSeen"      => (GreenBrush,  Colors.Green),
                    "Online"         => (GreenBrush,  Colors.Green),
                    "Offline"        => (YellowBrush, Colors.Gray),
                    "NewPort"        => (new SolidColorBrush(Color.FromRgb(255, 152, 0)), Colors.Orange),
                    "PortClosed"     => (YellowBrush, Colors.Yellow),
                    "ServiceChanged" => (new SolidColorBrush(Color.FromRgb(33, 150, 243)), Colors.Blue),
                    _                => (YellowBrush, Colors.Gray)
                };

                var row = new Border { Background = W_BgBrush(), CornerRadius = new CornerRadius(6), Margin = new Thickness(0, 0, 0, 4), Padding = new Thickness(10, 7, 10, 7) };
                var g = new Grid();
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var dot = new Ellipse { Width = 8, Height = 8, Fill = dotBrush, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
                Grid.SetColumn(dot, 0); g.Children.Add(dot);

                var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                info.Children.Add(new TextBlock { Text = asset.IPAddress ?? "Unknown", FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), TextTrimming = TextTrimming.CharacterEllipsis });
                info.Children.Add(new TextBlock { Text = ev.Detail, FontSize = 9, Opacity = 0.6, Foreground = W_TextBrush(), TextTrimming = TextTrimming.CharacterEllipsis });
                Grid.SetColumn(info, 1); g.Children.Add(info);

                var time = new TextBlock { Text = FormatRelativeTime(ev.Timestamp), FontSize = 9, Opacity = 0.5, Foreground = W_TextBrush(), VerticalAlignment = VerticalAlignment.Center };
                Grid.SetColumn(time, 2); g.Children.Add(time);

                row.Child = g;
                sp.Children.Add(row);
            }

            return sp;
        }

        // =========================================================================
        // IDS RULE STATS
        // =========================================================================
        private UIElement W_IdsRuleStats()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };

            List<IDSRule> rules = new();
            try { rules = IDSManager.Engine.Rules.ToList(); } catch { }

            int total   = rules.Count;
            int enabled = rules.Count(r => r.IsEnabled);
            var countBadge = W_Badge($"{enabled}/{total} active", new SolidColorBrush(Color.FromRgb(33, 150, 243)), 9);
            sp.Children.Add(W_Header(IconChar.Sliders, "IDS Rule Stats", Color.FromRgb(33, 150, 243), countBadge));

            if (!rules.Any())
            {
                sp.Children.Add(W_EmptyHint("No IDS rules loaded — configure the IDS engine first"));
                return sp;
            }

            // Rule kind strip
            int sig  = rules.Count(r => r.RuleKind == RuleKind.Signature);
            int behv = rules.Count(r => r.RuleKind == RuleKind.Behavioral);

            var kindGrid = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            kindGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            kindGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            kindGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            void AddKindCell(int col, string val, string lbl, Color c)
            {
                var cell = new Border { Background = new SolidColorBrush(Color.FromArgb(25, c.R, c.G, c.B)), CornerRadius = new CornerRadius(6), Padding = new Thickness(4, 6, 4, 6), Margin = new Thickness(col == 0 ? 0 : 3, 0, 0, 0) };
                var inner = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
                inner.Children.Add(new TextBlock { Text = val, FontSize = 18, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(c), HorizontalAlignment = HorizontalAlignment.Center });
                inner.Children.Add(new TextBlock { Text = lbl, FontSize = 9, Foreground = new SolidColorBrush(c), HorizontalAlignment = HorizontalAlignment.Center });
                cell.Child = inner;
                Grid.SetColumn(cell, col);
                kindGrid.Children.Add(cell);
            }
            AddKindCell(0, enabled.ToString(), "Enabled",    Color.FromRgb( 33, 150, 243));
            AddKindCell(1, sig.ToString(),     "Signature",  Color.FromRgb( 76, 175,  80));
            AddKindCell(2, behv.ToString(),    "Behavioral", Color.FromRgb(255, 152,   0));
            sp.Children.Add(kindGrid);

            var topRules = rules
                .Where(r => r.TriggerCount > 0)
                .OrderByDescending(r => r.TriggerCount)
                .Take(5).ToList();

            if (!topRules.Any())
            {
                sp.Children.Add(W_EmptyHint("Start IDS to accumulate rule trigger counts"));
                return sp;
            }

            sp.Children.Add(new TextBlock { Text = "Top Triggered Rules", FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), Opacity = 0.7, Margin = new Thickness(0, 0, 0, 6) });

            foreach (var r in topRules)
            {
                var sevColor = r.Severity switch
                {
                    IDSAlertSeverity.Critical => Color.FromRgb(244,  67, 54),
                    IDSAlertSeverity.High     => Color.FromRgb(255, 109,  0),
                    IDSAlertSeverity.Medium   => Color.FromRgb(255, 193,  7),
                    _                          => Color.FromRgb( 76, 175, 80)
                };

                var row = new Border { Background = W_BgBrush(), CornerRadius = new CornerRadius(6), Margin = new Thickness(0, 0, 0, 4), Padding = new Thickness(10, 7, 10, 7) };
                var g = new Grid();
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                info.Children.Add(new TextBlock { Text = r.Name ?? r.RuleId ?? "Unnamed Rule", FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), TextTrimming = TextTrimming.CharacterEllipsis });
                info.Children.Add(new TextBlock { Text = $"Last: {r.LastTriggeredFormatted}", FontSize = 9, Opacity = 0.55, Foreground = W_TextBrush() });
                Grid.SetColumn(info, 0); g.Children.Add(info);

                var badge = W_Badge($"{r.TriggerCount:N0} hits", new SolidColorBrush(sevColor), 9);
                Grid.SetColumn(badge, 1); g.Children.Add(badge);

                row.Child = g;
                sp.Children.Add(row);
            }

            return sp;
        }

        // =========================================================================
        // LIVE TRAFFIC
        // =========================================================================
        private UIElement W_LiveTraffic()
        {
            var sp = new StackPanel { Margin = new Thickness(16) };

            long totalPkts = 0, totalBytes = 0; bool capturing = false;
            double pps = 0, bps = 0;
            Dictionary<string, long> protocols = new();
            int threatCount = 0;

            try
            {
                var svc  = TrafficCaptureService.Instance;
                capturing  = svc.IsCapturing;
                totalPkts  = svc.Statistics.TotalPackets;
                totalBytes = svc.Statistics.TotalBytes;
                pps        = svc.Statistics.PacketsPerSecond;
                bps        = svc.Statistics.BytesPerSecond;
                threatCount = svc.Statistics.ThreatCount;
                protocols  = svc.Statistics.ProtocolPacketCounts ?? new();
            }
            catch { }

            var liveBadge = W_Badge(capturing ? "● LIVE" : "○ Idle",
                capturing ? new SolidColorBrush(Color.FromRgb(76, 175, 80)) : YellowBrush, 9);
            sp.Children.Add(W_Header(IconChar.WaveSquare, "Live Traffic", Color.FromRgb(76, 175, 80), liveBadge));

            // Big stat grid
            var numGrid = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            numGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            numGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            numGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            void AddBig(int col, string val, string lbl, Color c)
            {
                var cell = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
                cell.Children.Add(new TextBlock { Text = val, FontSize = 18, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(c), HorizontalAlignment = HorizontalAlignment.Center });
                cell.Children.Add(new TextBlock { Text = lbl, FontSize = 9, Opacity = 0.6, Foreground = W_TextBrush(), HorizontalAlignment = HorizontalAlignment.Center });
                Grid.SetColumn(cell, col);
                numGrid.Children.Add(cell);
            }
            AddBig(0, totalPkts.ToString("N0"),  "Packets",   Color.FromRgb( 76, 175, 80));
            AddBig(1, FormatBytesShort(totalBytes), "Captured", Color.FromRgb( 33, 150, 243));
            AddBig(2, threatCount.ToString(),    "Threats",   threatCount > 0 ? Color.FromRgb(244, 67, 54) : Color.FromRgb(120, 120, 120));
            sp.Children.Add(numGrid);

            // Rates (only meaningful while capturing)
            if (capturing && (pps > 0 || bps > 0))
            {
                var rateRow = new Grid { Margin = new Thickness(0, 0, 0, 8) };
                rateRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                rateRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                var ppsCell = new TextBlock { Text = $"{pps:N0} pkt/s", FontSize = 10, Foreground = new SolidColorBrush(Color.FromRgb(76, 175, 80)), HorizontalAlignment = HorizontalAlignment.Center };
                var bpsCell = new TextBlock { Text = $"{FormatBytesShort((long)bps)}/s", FontSize = 10, Foreground = new SolidColorBrush(Color.FromRgb(33, 150, 243)), HorizontalAlignment = HorizontalAlignment.Center };
                Grid.SetColumn(bpsCell, 1);
                rateRow.Children.Add(ppsCell);
                rateRow.Children.Add(bpsCell);
                sp.Children.Add(rateRow);
            }

            // Protocol mini-bars
            if (protocols.Any())
            {
                sp.Children.Add(new TextBlock { Text = "Protocol Mix", FontSize = 10, FontWeight = FontWeights.SemiBold, Foreground = W_TextBrush(), Opacity = 0.7, Margin = new Thickness(0, 0, 0, 6) });
                var top = protocols.OrderByDescending(x => x.Value).Take(5).ToList();
                double maxV = top.First().Value;
                var palette = new[] { Color.FromRgb(76,175,80), Color.FromRgb(33,150,243), Color.FromRgb(255,152,0), Color.FromRgb(156,39,176), Color.FromRgb(0,188,212) };
                int ci = 0;
                foreach (var kv in top)
                    sp.Children.Add(W_MiniBar(kv.Key, kv.Value, maxV, palette[ci++ % palette.Length]));
            }
            else
            {
                sp.Children.Add(W_EmptyHint("Start a capture to see live protocol data"));
            }

            return sp;
        }

        private static string FormatBytesShort(long bytes)
        {
            if (bytes <= 0) return "0 B";
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            int i = 0; double v = bytes;
            while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
            return $"{v:F1} {units[i]}";
        }

        // =========================================================================
        // Shared UI helpers
        // =========================================================================
        private Grid W_Header(IconChar icon, string title, Color iconColor, UIElement right = null)
        {
            var g = new Grid { Margin = new Thickness(0, 0, 0, 12) };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            if (right != null) g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var iconBorder = new Border
            {
                Background = new SolidColorBrush(iconColor),
                Width = 26, Height = 26, CornerRadius = new CornerRadius(7),
                Margin = new Thickness(0, 0, 9, 0),
                Child = new IconBlock { Icon = icon, Foreground = Brushes.White, Width = 12, Height = 12 }
            };
            Grid.SetColumn(iconBorder, 0);
            g.Children.Add(iconBorder);

            var titleTb = new TextBlock
            {
                Text = title, FontSize = 13, FontWeight = FontWeights.SemiBold,
                Foreground = W_TextBrush(), VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(titleTb, 1);
            g.Children.Add(titleTb);

            if (right != null)
            {
                var rightFe = right as FrameworkElement;
                if (rightFe != null)
                {
                    rightFe.VerticalAlignment = VerticalAlignment.Center;
                    Grid.SetColumn(rightFe, 2);
                    g.Children.Add(rightFe);
                }
            }

            return g;
        }

        private Border W_Badge(string text, Brush bg, double fontSize = 9)
        {
            return new Border
            {
                Background      = bg,
                CornerRadius    = new CornerRadius(4),
                Padding         = new Thickness(6, 2, 6, 2),
                VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock
                {
                    Text       = text,
                    FontSize   = fontSize,
                    Foreground = Brushes.White,
                    FontWeight = FontWeights.SemiBold,
                    VerticalAlignment = VerticalAlignment.Center
                }
            };
        }

        private Border W_MiniBar(string label, double value, double maxValue, Color barColor)
        {
            var outer = new Border { Margin = new Thickness(0, 0, 0, 5) };
            var g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Label + value
            var topRow = new Grid();
            topRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            topRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            topRow.Children.Add(new TextBlock { Text = label, FontSize = 10, Foreground = W_TextBrush(), TextTrimming = TextTrimming.CharacterEllipsis });
            var valTb = new TextBlock { Text = value.ToString("0"), FontSize = 9, Opacity = 0.7, Foreground = W_TextBrush() };
            Grid.SetColumn(valTb, 1);
            topRow.Children.Add(valTb);
            Grid.SetRow(topRow, 0);
            g.Children.Add(topRow);

            // Bar track + fill
            var track = new Border { Height = 5, Background = new SolidColorBrush(Color.FromArgb(30, barColor.R, barColor.G, barColor.B)), CornerRadius = new CornerRadius(3), Margin = new Thickness(0, 3, 0, 0) };
            var fill  = new Border { Height = 5, Background = new SolidColorBrush(barColor), CornerRadius = new CornerRadius(3), HorizontalAlignment = HorizontalAlignment.Left };
            double frac = maxValue > 0 ? Math.Max(value / maxValue, 0.02) : 0.02;
            track.SizeChanged += (_, e) => fill.Width = e.NewSize.Width * frac;
            var trackGrid = new Grid();
            trackGrid.Children.Add(track);
            trackGrid.Children.Add(fill);
            Grid.SetRow(trackGrid, 1);
            g.Children.Add(trackGrid);

            outer.Child = g;
            return outer;
        }

        private TextBlock W_EmptyHint(string text) =>
            new TextBlock
            {
                Text = text, FontSize = 11, Opacity = 0.4,
                Foreground = W_TextBrush(), TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 8, 0, 0)
            };

        // ── Theme brushes ─────────────────────────────────────────────────────────
        private Brush W_TextBrush()
        {
            try { return (Brush)Application.Current.Resources["TextBrush"]; }
            catch { return Brushes.WhiteSmoke; }
        }

        private Brush W_BgBrush()
        {
            try { return (Brush)Application.Current.Resources["BackgroundBrush"]; }
            catch { return Brushes.Transparent; }
        }

        private Brush W_SecBg()
        {
            try { return (Brush)Application.Current.Resources["SecondaryBackgroundBrush"]; }
            catch { return Brushes.Transparent; }
        }

        private Brush W_Border()
        {
            try { return (Brush)Application.Current.Resources["BorderBrush"]; }
            catch { return Brushes.Gray; }
        }
    }
}
