using System.Windows;
using System.Windows.Input;

namespace PROSCANNERCONT.Views
{
    /// <summary>Shows a (re)generated pairing code with a one-click Copy.</summary>
    public partial class PairingCodeDialog : Window
    {
        private readonly string _code;

        public PairingCodeDialog(string code)
        {
            InitializeComponent();
            _code = code;
            CodeBox.Text = code;
        }

        private void Copy_Click(object sender, RoutedEventArgs e)
        {
            try { Clipboard.SetDataObject(_code, true); CopyBtn.Content = "Copied ✓"; }
            catch { CopyBtn.Content = "Press Ctrl+C"; CodeBox.SelectAll(); CodeBox.Focus(); }
        }

        private void Done_Click(object sender, RoutedEventArgs e) => Close();

        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left) DragMove();
        }
    }
}
