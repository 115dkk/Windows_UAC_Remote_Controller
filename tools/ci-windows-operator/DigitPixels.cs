// SPDX-License-Identifier: GPL-2.0-or-later
// Six ASCII digits are recognized from actual GDI pixels, never a DTO/window text.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

internal static class DigitPixels
{
    private sealed class Glyph
    {
        internal int Width, Height;
        internal bool[,] Ink;
    }

    internal static string Read(Bitmap screenshot, int dpi)
    {
        Program.Require(dpi >= 96 && dpi <= 240, "ocr_dpi_rejected");
        int cardWidth = Math.Min(screenshot.Width * 72 / 100, 760 * dpi / 96);
        int cardHeight = Math.Min(screenshot.Height * 82 / 100, 820 * dpi / 96);
        int left = (screenshot.Width - cardWidth) / 2 + 36 * dpi / 96;
        int top = (screenshot.Height - cardHeight) / 2 + 170 * dpi / 96;
        int width = cardWidth - 72 * dpi / 96;
        int height = 90 * dpi / 96;
        Program.Require(left >= 0 && top >= 0 && left + width <= screenshot.Width && top + height <= screenshot.Height,
            "ocr_region_rejected");
        using (var region = screenshot.Clone(new Rectangle(left, top, width, height), PixelFormat.Format32bppRgb))
        {
            var actual = Split(region);
            Program.Require(actual.Count == 6, "ocr_six_glyphs_required");
            var templates = Templates(dpi);
            var digits = new StringBuilder(6);
            foreach (var glyph in actual)
            {
                double best = 1, runnerUp = 1;
                int winner = -1;
                for (int digit = 0; digit < 10; digit++)
                {
                    double error = Difference(glyph, templates[digit]);
                    if (error < best) { runnerUp = best; best = error; winner = digit; }
                    else if (error < runnerUp) runnerUp = error;
                }
                Program.Require(winner >= 0 && best <= 0.12 && runnerUp - best >= 0.03, "ocr_ambiguous");
                digits.Append((char)('0' + winner));
            }
            return digits.ToString();
        }
    }

    private static List<Glyph> Split(Bitmap bitmap)
    {
        var ink = new bool[bitmap.Width, bitmap.Height];
        var occupied = new bool[bitmap.Width];
        for (int y = 0; y < bitmap.Height; y++)
            for (int x = 0; x < bitmap.Width; x++)
            {
                Color color = bitmap.GetPixel(x, y);
                ink[x, y] = (color.R + color.G + color.B) / 3 < 140;
                occupied[x] |= ink[x, y];
            }
        var glyphs = new List<Glyph>();
        for (int x = 0; x < bitmap.Width; x++)
        {
            if (!occupied[x]) continue;
            int start = x;
            while (x + 1 < bitmap.Width && occupied[x + 1]) x++;
            int upper = bitmap.Height, lower = -1;
            for (int gx = start; gx <= x; gx++)
                for (int y = 0; y < bitmap.Height; y++)
                    if (ink[gx, y]) { upper = Math.Min(upper, y); lower = Math.Max(lower, y); }
            var glyph = new Glyph { Width = x - start + 1, Height = lower - upper + 1 };
            Program.Require(glyph.Width >= 3 && glyph.Height >= 12, "ocr_noise_rejected");
            glyph.Ink = new bool[glyph.Width, glyph.Height];
            for (int gx = 0; gx < glyph.Width; gx++)
                for (int y = 0; y < glyph.Height; y++) glyph.Ink[gx, y] = ink[gx + start, y + upper];
            glyphs.Add(glyph);
            Program.Require(glyphs.Count <= 10, "ocr_excess_glyphs");
        }
        return glyphs;
    }

    private static double Difference(Glyph a, Glyph b)
    {
        if (Math.Abs(a.Width - b.Width) > 2 || Math.Abs(a.Height - b.Height) > 2) return 1;
        double best = 1;
        for (int dx = -1; dx <= 1; dx++)
            for (int dy = -1; dy <= 1; dy++)
            {
                int mismatch = 0, union = 0;
                for (int y = -1; y <= Math.Max(a.Height, b.Height); y++)
                    for (int x = -1; x <= Math.Max(a.Width, b.Width); x++)
                    {
                        bool first = x >= 0 && y >= 0 && x < a.Width && y < a.Height && a.Ink[x, y];
                        int bx = x + dx, by = y + dy;
                        bool second = bx >= 0 && by >= 0 && bx < b.Width && by < b.Height && b.Ink[bx, by];
                        if (first || second) union++;
                        if (first != second) mismatch++;
                    }
                if (union != 0) best = Math.Min(best, (double)mismatch / union);
            }
        return best;
    }

    private static Glyph[] Templates(int dpi)
    {
        // Exact repository font is embedded at CI compile time. No runtime path,
        // downloaded OCR executable, clipboard, or application internal data.
        byte[] bytes;
        using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("UACSans-Bold.ttf"))
        {
            Program.Require(stream != null && stream.Length == 648272, "font_resource_rejected");
            bytes = new byte[(int)stream.Length];
            int offset = 0;
            while (offset < bytes.Length)
            {
                int read = stream.Read(bytes, offset, bytes.Length - offset);
                Program.Require(read > 0, "font_resource_truncated");
                offset += read;
            }
        }
        var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        IntPtr resource = IntPtr.Zero, font = IntPtr.Zero;
        try
        {
            uint count;
            resource = Native.AddFontMemResourceEx(pinned.AddrOfPinnedObject(), (uint)bytes.Length, IntPtr.Zero, out count);
            Program.Require(resource != IntPtr.Zero && count > 0, "font_registration_failed");
            font = Native.CreateFont(-(40 * dpi / 72), 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 5, 0, "UAC Sans");
            Program.Require(font != IntPtr.Zero, "font_creation_failed");
            var templates = new Glyph[10];
            for (int digit = 0; digit < 10; digit++)
            {
                using (var bitmap = new Bitmap(192, 192, PixelFormat.Format32bppRgb))
                {
                    using (var graphics = Graphics.FromImage(bitmap))
                    {
                        graphics.Clear(Color.White);
                        IntPtr dc = graphics.GetHdc();
                        IntPtr prior = Native.SelectObject(dc, font);
                        try
                        {
                            Native.SetTextColor(dc, 0x00352C15); // renderer RGB #152c35
                            Native.SetBkMode(dc, 1);
                            var rect = new Native.Rect { Left = 0, Top = 0, Right = 192, Bottom = 192 };
                            Program.Require(Native.DrawText(dc, digit.ToString(), 1, ref rect, 0x0001 | 0x0004 | 0x0020 | 0x0800) > 0,
                                "template_draw_failed");
                        }
                        finally { Native.SelectObject(dc, prior); graphics.ReleaseHdc(dc); }
                    }
                    var glyphs = Split(bitmap);
                    Program.Require(glyphs.Count == 1, "template_glyph_rejected");
                    templates[digit] = glyphs[0];
                }
            }
            return templates;
        }
        finally
        {
            if (font != IntPtr.Zero) Native.DeleteObject(font);
            if (resource != IntPtr.Zero) Native.RemoveFontMemResourceEx(resource);
            pinned.Free();
        }
    }
}
