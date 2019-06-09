using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;

namespace hidden_tear_decrypter
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

        public static void Restore()
        {
            var img = Image.FromFile("C:\\Users\\JRN\\Wallpapers\\WnAF0sm.jpg");
            
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
    }
}
