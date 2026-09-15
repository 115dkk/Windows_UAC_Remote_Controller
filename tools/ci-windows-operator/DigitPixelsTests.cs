// SPDX-License-Identifier: GPL-2.0-or-later
// Hosted native canary: only fixed PUBLIC text is drawn into owned memory GDI.
// No windows, UAC, input, clipboard, live screen pixels or artifact files.
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

internal static class DigitPixelsTests
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Rect { internal int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr window);
    [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr window, IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleBitmap(IntPtr dc, int width, int height);
    [DllImport("gdi32.dll")] private static extern bool DeleteDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr value);
    [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr dc, IntPtr value);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateSolidBrush(uint color);
    [DllImport("user32.dll")] private static extern int FillRect(IntPtr dc, ref Rect rect, IntPtr brush);
    [DllImport("gdi32.dll")] private static extern uint SetTextColor(IntPtr dc, uint color);
    [DllImport("gdi32.dll")] private static extern int SetBkMode(IntPtr dc, int mode);
    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFont(int height, int width, int escapement, int orientation,
        int weight, uint italic, uint underline, uint strike, uint charset, uint output, uint clip,
        uint quality, uint family, string face);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int DrawText(IntPtr dc, string text, int count, ref Rect rect, uint flags);
    [DllImport("gdi32.dll")] private static extern bool BitBlt(IntPtr target, int x, int y, int width,
        int height, IntPtr source, int sx, int sy, uint operation);
    [DllImport("gdi32.dll")] private static extern IntPtr AddFontMemResourceEx(IntPtr bytes,
        uint length, IntPtr reserved, out uint count);
    [DllImport("gdi32.dll")] private static extern bool RemoveFontMemResourceEx(IntPtr resource);

    private static void Check(bool value) { if (!value) throw new InvalidOperationException(); }
    private static bool Valid(IntPtr value) { return value != IntPtr.Zero && value != new IntPtr(-1); }
    private static uint ColorRef(uint rgb) { return ((rgb & 255) << 16) | (rgb & 0xff00) | (rgb >> 16); }

    private static void Fill(IntPtr dc, Rect rect, uint rgb)
    {
        IntPtr brush = CreateSolidBrush(ColorRef(rgb));
        Check(Valid(brush));
        try { Check(FillRect(dc, ref rect, brush) != 0); }
        finally { Check(DeleteObject(brush)); }
    }

    // Independent composition of the product's draw/draw_comparison operations.
    // Do not call the OCR's template builder or use managed Graphics.DrawString.
    private static Bitmap Render(string text, int dpi)
    {
        Bitmap result = null;
        try
        {
            // Model the renderer's separate process: both target fonts are
            // unloaded before the caller invokes the operator's DigitPixels.Read.
            // In particular, its templates must not inherit our regular face.
            using (var regular = new RegisteredFont("UACSans-Regular.ttf", 646148))
            using (var bold = new RegisteredFont("UACSans-Bold.ttf", 648272))
                result = RenderRegistered(text, dpi);
            return result;
        }
        catch { if (result != null) result.Dispose(); throw; }
    }

    private static Bitmap RenderRegistered(string text, int dpi)
    {
        int width = 1280 * dpi / 96, height = 800 * dpi / 96;
        int cardWidth = Math.Min(width * 72 / 100, 760 * dpi / 96);
        int cardHeight = Math.Min(height * 96 / 100, 900 * dpi / 96);
        int left = (width - cardWidth) / 2, top = (height - cardHeight) / 2;
        IntPtr screen = IntPtr.Zero, memory = IntPtr.Zero, bitmap = IntPtr.Zero, font = IntPtr.Zero;
        IntPtr oldBitmap = IntPtr.Zero, oldFont = IntPtr.Zero;
        Bitmap result = null;
        try
        {
            // Screen DC supplies only the device format; no screen pixels are read.
            screen = GetDC(IntPtr.Zero); Check(Valid(screen));
            memory = CreateCompatibleDC(screen); Check(Valid(memory));
            bitmap = CreateCompatibleBitmap(screen, width, height); Check(Valid(bitmap));
            oldBitmap = SelectObject(memory, bitmap); Check(Valid(oldBitmap));
            Fill(memory, new Rect { Right = width, Bottom = height }, 0xf2f6f7);
            Fill(memory, new Rect { Left = left, Top = top, Right = left + cardWidth, Bottom = top + cardHeight }, 0xd7e3e7);
            Fill(memory, new Rect { Left = left + 1, Top = top + 1, Right = left + cardWidth - 1, Bottom = top + cardHeight - 1 }, 0xffffff);
            font = CreateFont(-(40 * dpi / 72), 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 5, 0, "UAC Sans");
            Check(Valid(font));
            oldFont = SelectObject(memory, font); Check(Valid(oldFont));
            Check(SetBkMode(memory, 1) != 0);
            Check(SetTextColor(memory, ColorRef(0x152c35)) != 0xffffffff);
            var code = new Rect { Left = left + 36 * dpi / 96, Top = top + 196 * dpi / 96,
                Right = left + cardWidth - 36 * dpi / 96, Bottom = top + 260 * dpi / 96 };
            Check(DrawText(memory, text, text.Length, ref code, 0x0001 | 0x0004 | 0x0020 | 0x0800) > 0);
            // Mirror capture's BitBlt into the managed RGB bitmap, but the source
            // is exclusively this fixture's freshly painted memory surface.
            result = new Bitmap(width, height, PixelFormat.Format32bppRgb);
            using (var graphics = Graphics.FromImage(result))
            {
                IntPtr target = graphics.GetHdc();
                try { Check(BitBlt(target, 0, 0, width, height, memory, 0, 0, 0x00cc0020)); }
                finally { graphics.ReleaseHdc(target); }
            }
            return result;
        }
        catch { if (result != null) result.Dispose(); throw; }
        finally
        {
            // Restore selections before releasing owned GDI objects. Attempt all
            // cleanup even when one OS operation reports failure; then fail CI.
            bool cleaned = true;
            if (Valid(oldFont)) cleaned &= Valid(SelectObject(memory, oldFont));
            if (Valid(oldBitmap)) cleaned &= Valid(SelectObject(memory, oldBitmap));
            if (font != IntPtr.Zero) cleaned &= DeleteObject(font);
            if (bitmap != IntPtr.Zero) cleaned &= DeleteObject(bitmap);
            if (memory != IntPtr.Zero) cleaned &= DeleteDC(memory);
            if (screen != IntPtr.Zero) cleaned &= ReleaseDC(IntPtr.Zero, screen) != 0;
            if (!cleaned && result != null) result.Dispose();
            Check(cleaned);
        }
    }

    private static void Reject(Bitmap pixels, int dpi, params string[] gates)
    {
        try { DigitPixels.Read(pixels, dpi); }
        catch (Program.GateFailure failure)
        {
            if (Array.IndexOf(gates, failure.Code) < 0) throw;
            return;
        }
        throw new InvalidOperationException();
    }

    private sealed class RegisteredFont : IDisposable
    {
        private GCHandle pinned;
        private IntPtr resource;
        internal RegisteredFont(string name, int size)
        {
            byte[] bytes;
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
            {
                Check(stream != null && stream.Length == size);
                bytes = new byte[(int)stream.Length];
                int offset = 0;
                while (offset < bytes.Length)
                {
                    int count = stream.Read(bytes, offset, bytes.Length - offset);
                    Check(count > 0); offset += count;
                }
            }
            pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                uint count;
                resource = AddFontMemResourceEx(pinned.AddrOfPinnedObject(), (uint)bytes.Length, IntPtr.Zero, out count);
                Check(resource != IntPtr.Zero && count > 0);
            }
            catch { Dispose(); throw; }
        }
        public void Dispose()
        {
            bool removed = resource == IntPtr.Zero || RemoveFontMemResourceEx(resource);
            resource = IntPtr.Zero;
            if (pinned.IsAllocated) pinned.Free();
            Check(removed);
        }
    }

    private static int Main(string[] args)
    {
        string stage = "startup";
        int testedDpi = 0;
        using (var watchdog = new Timer(_ => Environment.Exit(124), null, 120000, Timeout.Infinite))
        {
            try
            {
                if (args.Length != 0 || Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
                    Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted") return 2;
                foreach (int dpi in new[] { 96, 120, 144, 192, 240 })
                {
                    testedDpi = dpi;
                    stage = "positive_digits";
                    foreach (string text in new[] { "012345", "678901", "222333" })
                        using (var pixels = Render(text, dpi)) Check(DigitPixels.Read(pixels, dpi) == text);
                    stage = "positive_grouped_digits";
                    foreach (string text in new[] { "012345", "678901", "222333" })
                        using (var pixels = Render(text.Insert(3, " "), dpi)) Check(DigitPixels.Read(pixels, dpi) == text);
                    stage = "glyph_count_negative";
                    using (var pixels = Render("12345", dpi)) Reject(pixels, dpi, "ocr_six_glyphs_required");
                    using (var pixels = Render("1234567", dpi)) Reject(pixels, dpi, "ocr_six_glyphs_required");
                    stage = "nondigit_negative";
                        // Separate nondigit glyphs so this probes recognition,
                        // not adjacent letters merging into fewer ink columns.
                        using (var pixels = Render("W W W W W W", dpi))
                        Reject(pixels, dpi, "ocr_no_matching_glyph", "ocr_glyph_difference", "ocr_not_unique");
                    stage = "noise_negative";
                    using (var pixels = Render("012345", dpi))
                    {
                        int cardWidth = Math.Min(pixels.Width * 72 / 100, 760 * dpi / 96);
                        int cardHeight = Math.Min(pixels.Height * 96 / 100, 900 * dpi / 96);
                        int x = (pixels.Width - cardWidth) / 2 + 36 * dpi / 96 + 1;
                        int y = (pixels.Height - cardHeight) / 2 + 196 * dpi / 96 + 1;
                        pixels.SetPixel(x, y, Color.Black);
                        Reject(pixels, dpi, "ocr_noise_rejected");
                    }
                }
                stage = "invalid_input_negative";
                using (var pixels = Render("012345", 96))
                {
                    Reject(pixels, 95, "ocr_dpi_rejected");
                    Reject(pixels, 241, "ocr_dpi_rejected");
                }
                using (var pixels = new Bitmap(100, 100)) Reject(pixels, 96, "ocr_region_rejected");
                Console.WriteLine("Public GDI digit canary passed: 30 positive, 23 negative controls.");
                return 0;
            }
            catch (Program.GateFailure failure)
            {
                // Project only the closed OCR failure classes needed for the
                // public canary; never forward an arbitrary exception message.
                string gate = Array.IndexOf(new[] { "ocr_no_matching_glyph", "ocr_glyph_difference",
                    "ocr_not_unique", "ocr_six_glyphs_required", "ocr_noise_rejected" }, failure.Code) >= 0
                    ? failure.Code : "other_gate";
                Console.Error.WriteLine("Public GDI digit canary failed: stage={0} dpi={1} gate={2}", stage, testedDpi, gate);
                return 1;
            }
            catch
            {
                Console.Error.WriteLine("Public GDI digit canary failed: stage={0} dpi={1}", stage, testedDpi);
                return 1;
            }
        }
    }
}
