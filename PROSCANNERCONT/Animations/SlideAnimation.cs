using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace PROSCANNERCONT.Animations
{
    public class SlideAnimation
    {
        private readonly TranslateTransform _transform;
        private readonly double _collapsedX;
        private readonly double _expandedX;
        private readonly Duration _duration = new Duration(TimeSpan.FromSeconds(0.3));

        public SlideAnimation(TranslateTransform transform, double collapsedX = 240, double expandedX = 0)
        {
            _transform = transform;
            _collapsedX = collapsedX;
            _expandedX = expandedX;
        }

        public void SlideIn()
        {
            var animation = new DoubleAnimation
            {
                From = _collapsedX,
                To = _expandedX,
                Duration = _duration,
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            };
            _transform.BeginAnimation(TranslateTransform.XProperty, animation);
        }

        public void SlideOut()
        {
            var animation = new DoubleAnimation
            {
                From = _expandedX,
                To = _collapsedX,
                Duration = _duration,
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            };
            _transform.BeginAnimation(TranslateTransform.XProperty, animation);
        }
    }
}