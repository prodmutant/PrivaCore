using System;
using System.Windows;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Services;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    public partial class VMSettingsWindow : Window
    {
        private HoneypotVM _vm;
        private HyperVManager _hyperVManager;
        private bool _hasChanges = false;

        public VMSettingsWindow(HoneypotVM vm, HyperVManager hyperVManager)
        {
            InitializeComponent();
            _vm = vm;
            _hyperVManager = hyperVManager;

            InitializeSettings();
        }

        private void InitializeSettings()
        {
            VMNameText.Text = $"Settings: {_vm.Name}";

            // Set current values
            MemorySlider.Value = _vm.MemoryMB;
            CPUSlider.Value = _vm.CPUCores;

            UpdateCurrentConfig();
        }

        private void MemorySlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (MemoryValueText != null)
            {
                int value = (int)e.NewValue;
                MemoryValueText.Text = $"{value} MB";
                _hasChanges = true;
                UpdateCurrentConfig();
            }
        }

        private void CPUSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (CPUValueText != null)
            {
                int value = (int)e.NewValue;
                CPUValueText.Text = $"{value} Core{(value > 1 ? "s" : "")}";
                _hasChanges = true;
                UpdateCurrentConfig();
            }
        }

        private void UpdateCurrentConfig()
        {
            if (CurrentConfigText == null) return;

            int newMemory = (int)MemorySlider.Value;
            int newCPU = (int)CPUSlider.Value;

            CurrentConfigText.Text = $"VM: {_vm.Name}\n" +
                                    $"Memory: {newMemory} MB (Current: {_vm.MemoryMB} MB)\n" +
                                    $"CPU: {newCPU} cores (Current: {_vm.CPUCores} cores)\n" +
                                    $"Status: {_vm.StatusText}";
        }

        private async void ApplyButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_hasChanges)
            {
                AppDialog.Show("No changes to apply.", "Info",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // Check if VM is running
            if (_vm.Status == HoneypotStatus.Running)
            {
                var result = AppDialog.Show(
                    "The VM is currently running. Changes to memory and CPU require the VM to be stopped.\n\n" +
                    "Do you want to stop the VM and apply changes?",
                    "VM Running",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.No)
                {
                    return;
                }

                try
                {
                    // Stop VM
                    ApplyButton.IsEnabled = false;
                    ApplyButton.Content = "Stopping VM...";

                    await _hyperVManager.StopVM(_vm.HyperVVMId);
                    _vm.Status = HoneypotStatus.Stopped;
                }
                catch (Exception ex)
                {
                    AppDialog.Show($"Failed to stop VM: {ex.Message}",
                        "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    ApplyButton.IsEnabled = true;
                    ApplyButton.Content = "Apply Changes";
                    return;
                }
            }

            try
            {
                ApplyButton.Content = "Applying changes...";

                int newMemory = (int)MemorySlider.Value;
                int newCPU = (int)CPUSlider.Value;

                // Apply memory changes
                if (newMemory != _vm.MemoryMB)
                {
                    await _hyperVManager.UpdateVMMemory(_vm.HyperVVMId, newMemory);
                    _vm.MemoryMB = newMemory;
                }

                // Apply CPU changes
                if (newCPU != _vm.CPUCores)
                {
                    await _hyperVManager.UpdateVMCPU(_vm.HyperVVMId, newCPU);
                    _vm.CPUCores = newCPU;
                }

                AppDialog.Show("Settings applied successfully!",
                    "Success", MessageBoxButton.OK, MessageBoxImage.Information);

                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                AppDialog.Show($"Failed to apply settings: {ex.Message}",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ApplyButton.IsEnabled = true;
                ApplyButton.Content = "Apply Changes";
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            if (_hasChanges)
            {
                var result = AppDialog.Show(
                    "You have unsaved changes. Are you sure you want to close?",
                    "Unsaved Changes",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.No)
                {
                    return;
                }
            }

            DialogResult = false;
            Close();
        }
    }
}


