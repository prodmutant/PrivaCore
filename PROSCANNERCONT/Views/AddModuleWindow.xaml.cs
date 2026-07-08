using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using FontAwesome.Sharp;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;

namespace PROSCANNERCONT.Views
{
    public partial class AddModuleWindow : Window
    {
        /// <summary>Raised when a module is added, so the host window can refresh its nav.</summary>
        public event Action? ModuleAdded;

        public AddModuleWindow()
        {
            InitializeComponent();
            CardList.ItemsSource = ModuleCatalog.All.Select(d => new ModuleCardVm(d)).ToList();
        }

        private void AddCard_Click(object sender, RoutedEventArgs e)
        {
            if (sender is FrameworkElement fe && fe.Tag is ModuleCardVm vm && vm.CanAdd)
            {
                ModuleRegistry.Instance.Add(vm.Descriptor);
                vm.MarkAdded();
                ModuleAdded?.Invoke();
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left) DragMove();
        }
    }

    /// <summary>View-model for one module card in the picker.</summary>
    public sealed class ModuleCardVm : INotifyPropertyChanged
    {
        public ModuleDescriptor Descriptor { get; }

        public ModuleCardVm(ModuleDescriptor d)
        {
            Descriptor = d;
            if (d.IsPlaceholder) { _buttonText = "Coming soon"; _canAdd = false; }
            else { _buttonText = ModuleRegistry.Instance.Contains(d.Key) ? "Add another" : "Add"; _canAdd = true; }
        }

        public IconChar Icon => Descriptor.Icon;
        public string Name => Descriptor.DisplayName;
        public string Description => Descriptor.Description;
        public string Category => Descriptor.Category;
        public double Opacity => Descriptor.IsPlaceholder ? 0.55 : 1.0;

        private string _buttonText;
        public string ButtonText { get => _buttonText; private set { _buttonText = value; OnPropertyChanged(nameof(ButtonText)); } }

        private bool _canAdd;
        public bool CanAdd { get => _canAdd; private set { _canAdd = value; OnPropertyChanged(nameof(CanAdd)); } }

        public void MarkAdded() { ButtonText = "Add another"; }   // stays enabled — add as many as you like

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }
}
