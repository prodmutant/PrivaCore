using System.Windows;

namespace PrivaCore.SIEM;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        PROSCANNERCONT.Managers.ThemeManager.LoadAndApply();   // honour the local saved theme
        var shell = new Shell();
        MainWindow = shell;
        shell.Show();
    }
}
