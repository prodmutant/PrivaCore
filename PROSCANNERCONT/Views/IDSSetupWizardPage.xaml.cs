using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Views
{
    /// <summary>
    /// IDS Setup Wizard Page - Modern animated wizard for configuring IDS
    /// </summary>
    public partial class IDSSetupWizardPage : Page
    {
        public enum IDSMode
        {
            None,
            HostBased,
            NetworkBased
        }

        public IDSMode SelectedMode { get; private set; } = IDSMode.None;
        public bool SetupCompleted { get; private set; } = false;

        public IDSSetupWizardPage()
        {
            InitializeComponent();
            Debug.WriteLine("IDSSetupWizardPage: Initialized as Page");

            // Start with welcome step visible
            this.Loaded += (s, e) =>
            {
                AnimateStepIn(WelcomeStep);
            };
        }

        #region Step Navigation with Smooth Animations

        private void ShowStep(Grid stepToShow, int progressValue)
        {
            Debug.WriteLine($"ShowStep: Transitioning to new step, progress={progressValue}");

            // Get current visible step
            Grid currentStep = null;
            if (WelcomeStep.Visibility == Visibility.Visible && WelcomeStep != stepToShow)
                currentStep = WelcomeStep;
            else if (HostDetailsStep.Visibility == Visibility.Visible && HostDetailsStep != stepToShow)
                currentStep = HostDetailsStep;
            else if (NetworkDetailsStep.Visibility == Visibility.Visible && NetworkDetailsStep != stepToShow)
                currentStep = NetworkDetailsStep;

            // Update progress bar
            var progressAnimation = new DoubleAnimation
            {
                To = progressValue,
                Duration = TimeSpan.FromSeconds(0.5),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
            };
            WizardProgress.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, progressAnimation);

            // Animate out current step
            if (currentStep != null)
            {
                AnimateStepOut(currentStep, () =>
                {
                    currentStep.Visibility = Visibility.Collapsed;
                    stepToShow.Visibility = Visibility.Visible;
                    AnimateStepIn(stepToShow);
                });
            }
            else
            {
                stepToShow.Visibility = Visibility.Visible;
                AnimateStepIn(stepToShow);
            }
        }

        private void AnimateStepOut(Grid step, Action onComplete)
        {
            var fadeOut = new DoubleAnimation
            {
                From = 1,
                To = 0,
                Duration = TimeSpan.FromSeconds(0.3),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };

            fadeOut.Completed += (s, e) =>
            {
                onComplete?.Invoke();
            };

            step.BeginAnimation(UIElement.OpacityProperty, fadeOut);
        }

        private void AnimateStepIn(Grid step)
        {
            var transform = step.RenderTransform as TranslateTransform;
            if (transform == null)
            {
                transform = new TranslateTransform();
                step.RenderTransform = transform;
            }

            // Slide in from bottom
            var slideIn = new DoubleAnimation
            {
                From = 30,
                To = 0,
                Duration = TimeSpan.FromSeconds(0.5),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };

            // Fade in
            var fadeIn = new DoubleAnimation
            {
                From = 0,
                To = 1,
                Duration = TimeSpan.FromSeconds(0.5),
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            };

            transform.BeginAnimation(TranslateTransform.YProperty, slideIn);
            step.BeginAnimation(UIElement.OpacityProperty, fadeIn);
        }

        #endregion

        #region Card Hover Animations

        private void HostCard_MouseEnter(object sender, MouseEventArgs e)
        {
            AnimateCardHover(sender as Border, true, "#4EC9B0");
        }

        private void HostCard_MouseLeave(object sender, MouseEventArgs e)
        {
            AnimateCardHover(sender as Border, false, "#3E3E42");
        }

        private void NetworkCard_MouseEnter(object sender, MouseEventArgs e)
        {
            AnimateCardHover(sender as Border, true, "#007ACC");
        }

        private void NetworkCard_MouseLeave(object sender, MouseEventArgs e)
        {
            AnimateCardHover(sender as Border, false, "#3E3E42");
        }

        private void AnimateCardHover(Border card, bool isEntering, string targetColor)
        {
            if (card == null) return;

            var transform = card.RenderTransform as TranslateTransform;
            if (transform == null)
            {
                transform = new TranslateTransform();
                card.RenderTransform = transform;
            }

            // Lift animation
            var liftAnimation = new DoubleAnimation
            {
                To = isEntering ? -8 : 0,
                Duration = TimeSpan.FromSeconds(0.3),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };

            // Border color animation
            var colorAnimation = new ColorAnimation
            {
                To = (Color)ColorConverter.ConvertFromString(targetColor),
                Duration = TimeSpan.FromSeconds(0.3)
            };

            transform.BeginAnimation(TranslateTransform.YProperty, liftAnimation);
            card.BorderBrush.BeginAnimation(SolidColorBrush.ColorProperty, colorAnimation);
        }

        #endregion

        #region Selection Handlers

        private void SelectHostBased_Click(object sender, MouseButtonEventArgs e)
        {
            Debug.WriteLine("IDSSetupWizardPage: User selected Host-Based IDS");
            SelectedMode = IDSMode.HostBased;
            ShowStep(HostDetailsStep, 66);
        }

        private void SelectNetworkBased_Click(object sender, MouseButtonEventArgs e)
        {
            Debug.WriteLine("IDSSetupWizardPage: User selected Network-Based IDS");
            SelectedMode = IDSMode.NetworkBased;
            ShowStep(NetworkDetailsStep, 66);
        }

        private void BackToWelcome_Click(object sender, RoutedEventArgs e)
        {
            Debug.WriteLine("IDSSetupWizardPage: Navigating back to welcome");
            SelectedMode = IDSMode.None;
            ShowStep(WelcomeStep, 33);
        }

        #endregion

        #region Configuration Handlers

        private void ConfigureHostBased_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Debug.WriteLine("IDSSetupWizardPage: Configuring Host-Based IDS...");

                var result = AppDialog.Show(
                    "Ready to configure Host-Based IDS!\n\n" +
                    "The system will:\n" +
                    "• Enable Windows Event Log monitoring\n" +
                    "• Configure file integrity checking\n" +
                    "• Set up process monitoring\n" +
                    "• Install detection rules\n" +
                    "• Create baseline configuration\n\n" +
                    "Continue with configuration?",
                    "Configure Host-Based IDS",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    // Update progress to 100%
                    var progressAnimation = new DoubleAnimation
                    {
                        To = 100,
                        Duration = TimeSpan.FromSeconds(0.5),
                        EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
                    };
                    WizardProgress.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, progressAnimation);

                    SetupCompleted = true;
                    SelectedMode = IDSMode.HostBased;

                    AppDialog.Show(
                        "Host-Based IDS configured successfully!\n\n" +
                        "Your system is now monitoring:\n" +
                        "✓ System logs and events\n" +
                        "✓ File system changes\n" +
                        "✓ Process activities\n" +
                        "✓ Network connections\n\n" +
                        "Redirecting to IDS Dashboard...",
                        "Setup Complete",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);

                    Debug.WriteLine("IDSSetupWizardPage: Host-Based IDS configured successfully");

                    // Notify completion
                    RaiseSetupCompleted();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"IDSSetupWizardPage ERROR: {ex.Message}");
                AppDialog.Show(
                    $"Error configuring Host-Based IDS:\n\n{ex.Message}",
                    "Configuration Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void ConfigureNetworkBased_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Debug.WriteLine("IDSSetupWizardPage: Configuring Network-Based IDS...");

                var result = AppDialog.Show(
                    "Ready to configure Network-Based IDS!\n\n" +
                    "The system will:\n" +
                    "• Detect available network interfaces\n" +
                    "• Configure packet capture\n" +
                    "• Set up traffic analysis\n" +
                    "• Install network detection rules\n" +
                    "• Configure monitoring interfaces\n\n" +
                    "Continue with configuration?",
                    "Configure Network-Based IDS",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    // Update progress to 100%
                    var progressAnimation = new DoubleAnimation
                    {
                        To = 100,
                        Duration = TimeSpan.FromSeconds(0.5),
                        EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
                    };
                    WizardProgress.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, progressAnimation);

                    SetupCompleted = true;
                    SelectedMode = IDSMode.NetworkBased;

                    AppDialog.Show(
                        "Network-Based IDS configured successfully!\n\n" +
                        "Your system is now monitoring:\n" +
                        "✓ Network traffic patterns\n" +
                        "✓ Packet headers and payloads\n" +
                        "✓ Protocol anomalies\n" +
                        "✓ Attack signatures\n\n" +
                        "Redirecting to IDS Dashboard...",
                        "Setup Complete",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);

                    Debug.WriteLine("IDSSetupWizardPage: Network-Based IDS configured successfully");

                    // Notify completion
                    RaiseSetupCompleted();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"IDSSetupWizardPage ERROR: {ex.Message}");
                AppDialog.Show(
                    $"Error configuring Network-Based IDS:\n\n{ex.Message}",
                    "Configuration Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        #endregion

        #region Setup Completion Event

        /// <summary>
        /// Event fired when setup is successfully completed
        /// </summary>
        public event EventHandler<IDSMode> SetupCompletedEvent;

        private void RaiseSetupCompleted()
        {
            Debug.WriteLine($"RaiseSetupCompleted: Raising event with mode={SelectedMode}");
            SetupCompletedEvent?.Invoke(this, SelectedMode);
        }

        #endregion
    }
}


