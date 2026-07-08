using System;
using System.Collections.Generic;

namespace PROSCANNERCONT.Models
{
    /// <summary>
    /// A squarified treemap layout (Bruls/Huizing/van Wijk): packs weighted items into a rectangle
    /// as near-square tiles whose areas are proportional to their values. Pure + dependency-free so it
    /// can drive a WPF treemap tile and be unit-tested without any UI.
    /// </summary>
    public static class SiemTreemap
    {
        /// <summary>One laid-out tile. <see cref="Index"/> is the position in the original input list.</summary>
        public readonly record struct Tile(double X, double Y, double W, double H, int Index);

        private sealed class Rect { public double X, Y, W, H; }

        public static List<Tile> Layout(IReadOnlyList<double> values, double width, double height)
        {
            var tiles = new List<Tile>();
            if (values == null || width <= 0 || height <= 0) return tiles;

            var items = new List<(double v, int idx)>();
            for (int i = 0; i < values.Count; i++) if (values[i] > 0) items.Add((values[i], i));
            items.Sort((a, b) => b.v.CompareTo(a.v));   // largest first
            double total = 0; foreach (var it in items) total += it.v;
            if (total <= 0) return tiles;

            double scale = width * height / total;
            var areas = new List<(double area, int idx)>(items.Count);
            foreach (var it in items) areas.Add((it.v * scale, it.idx));

            var rect = new Rect { X = 0, Y = 0, W = width, H = height };
            var row = new List<(double area, int idx)>();
            int pos = 0;
            while (pos < areas.Count)
            {
                double side = Math.Min(rect.W, rect.H);
                var candidate = areas[pos];
                if (row.Count == 0 || Worst(row, side) >= WorstWith(row, candidate, side))
                {
                    row.Add(candidate);
                    pos++;
                }
                else
                {
                    LayoutRow(row, rect, tiles);
                    row.Clear();
                }
            }
            if (row.Count > 0) LayoutRow(row, rect, tiles);
            return tiles;
        }

        private static double Worst(List<(double area, int idx)> row, double side)
        {
            double s = 0, mn = double.MaxValue, mx = 0;
            foreach (var r in row) { s += r.area; if (r.area < mn) mn = r.area; if (r.area > mx) mx = r.area; }
            if (s <= 0 || side <= 0) return double.MaxValue;
            double side2 = side * side, s2 = s * s;
            return Math.Max(side2 * mx / s2, s2 / (side2 * mn));
        }

        private static double WorstWith(List<(double area, int idx)> row, (double area, int idx) extra, double side)
        {
            row.Add(extra);
            double w = Worst(row, side);
            row.RemoveAt(row.Count - 1);
            return w;
        }

        /// <summary>Lay a finished row as a strip along the rectangle's shorter side, then shrink the rectangle.</summary>
        private static void LayoutRow(List<(double area, int idx)> row, Rect rect, List<Tile> tiles)
        {
            double s = 0; foreach (var r in row) s += r.area;
            if (s <= 0) return;
            if (rect.W <= rect.H)
            {
                double stripH = s / rect.W;
                double x = rect.X;
                foreach (var it in row) { double w = it.area / stripH; tiles.Add(new Tile(x, rect.Y, w, stripH, it.idx)); x += w; }
                rect.Y += stripH; rect.H -= stripH;
            }
            else
            {
                double stripW = s / rect.H;
                double y = rect.Y;
                foreach (var it in row) { double h = it.area / stripW; tiles.Add(new Tile(rect.X, y, stripW, h, it.idx)); y += h; }
                rect.X += stripW; rect.W -= stripW;
            }
        }
    }
}
