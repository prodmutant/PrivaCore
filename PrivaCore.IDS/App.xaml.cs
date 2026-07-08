using System.Windows;
using PROSCANNERCONT.Managers;
using PROSCANNERCONT.Services;

namespace PrivaCore.IDS;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        try { ThemeManager.LoadAndApply(); } catch { }
        try { ThemeManager.Apply("Phantom Dark"); } catch { }
        try { ConfigManager.TryLoadLastConfig(); } catch { }

        var shell = new PROSCANNERCONT.MainWindow();   // the IDS module shell
        MainWindow = shell;
        shell.Show();
    }
}
