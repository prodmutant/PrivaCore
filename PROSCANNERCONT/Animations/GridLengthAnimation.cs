using System;
using System.Windows;
using System.Windows.Media.Animation;

namespace PROSCANNERCONT.Animations
{
    public class GridLengthAnimation : AnimationTimeline
    {
        public override Type TargetPropertyType => typeof(GridLength);

        protected override Freezable CreateInstanceCore() => new GridLengthAnimation();

        public GridLength From
        {
            get => (GridLength)GetValue(FromProperty);
            set => SetValue(FromProperty, value);
        }
        public static readonly DependencyProperty FromProperty =
            DependencyProperty.Register(nameof(From), typeof(GridLength), typeof(GridLengthAnimation));

        public GridLength To
        {
            get => (GridLength)GetValue(ToProperty);
            set => SetValue(ToProperty, value);
        }
        public static readonly DependencyProperty ToProperty =
            DependencyProperty.Register(nameof(To), typeof(GridLength), typeof(GridLengthAnimation));

        // Optional easing — applied to the linear progress before interpolating
        public IEasingFunction? EasingFunction { get; set; }

        public override object GetCurrentValue(object defaultOriginValue,
            object defaultDestinationValue, AnimationClock animationClock)
        {
            if (animationClock.CurrentProgress == null)
                return new GridLength(0);

            double progress = animationClock.CurrentProgress.Value;
            if (EasingFunction != null)
                progress = EasingFunction.Ease(progress);

            double from = From.Value;
            double to   = To.Value;
            return new GridLength(from + (to - from) * progress,
                From.IsStar ? GridUnitType.Star : GridUnitType.Pixel);
        }
    }
}
