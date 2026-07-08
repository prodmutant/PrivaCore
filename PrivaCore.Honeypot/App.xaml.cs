using System.Windows;
using PROSCANNERCONT.Managers;

namespace PrivaCore.Honeypot;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        try { ThemeManager.LoadAndApply(); } catch { }
        try { ThemeManager.Apply("Phantom Dark"); } catch { }

        var shell = new Shell();   // the honeypot sensor shell
        MainWindow = shell;
        shell.Show();
    }
}
