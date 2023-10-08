using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using PSTParse;
using PSTParse.Message_Layer;
using MiscParseUtilities;


namespace PST_PasswordRecovery
    {
    class Program
    {
      static  int  toprintableASCII2(int a)
        {
            return (a) < 10 ? (a) + '0' : (a) < 36 ? ((a) - 10 + 'A') : (a) - 36 + 'a';
        }
        static void Main(string[] args)
        {
            
            if (args.Length > 0 && File.Exists(args[0]))
            {
                Console.WriteLine("PST_PasswordRecovery 0.1 - Twitter @solver_re");
                Console.WriteLine("File: "+ Path.GetFileName(args[0]));
            }
            else {
                Console.WriteLine("Trascina il file PST sull'applicazione per tentare il recupero della password.");
                Console.WriteLine("Drag and drop the PST file over the exe to recover password.");
                Console.Read();
                return;
            }
            var sw = new Stopwatch();
            sw.Start();
            var pstPath = args[0];

            var pstSize = new FileInfo(pstPath).Length*1.0/1024/1024;
            using (var file = new PSTFile(pstPath))
            {
                var pc = new PSTParse.LTP.PropertyContext(PSTParse.NDB.SpecialNIDs.NID_MESSAGE_STORE, file);
                var passwordset = pc.Properties.FirstOrDefault(t => t.Key == 0x67ff);
                if (passwordset.Key == 0x67ff && !passwordset.Value.Data.SequenceEqual(new byte[] { 0x0, 0x0, 0x0, 0x0 }))
                {
                    Console.WriteLine("Password impostata/Password enabled");
                    Console.WriteLine("Password CRC: " + ByteArrayToString(passwordset.Value.Data));

                    var result = (new CRC32_PW()).findReverseAscii(BitConverter.ToUInt32(passwordset.Value.Data, 0));
                    Console.WriteLine("Password collidente / Collision Password: " + CharArrayToString(result));

                }
                else
                    Console.WriteLine("Password NON impostata / PST with no password set");

                sw.Stop();


                Console.WriteLine("Elaborato {0} ({2:0.00} MB) in {1} milliseconds", Path.GetFileName(pstPath),
                                  sw.ElapsedMilliseconds, pstSize);
                Console.Read();
                return;
            }
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
        public static string CharArrayToString(char[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (char b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

    }


}
