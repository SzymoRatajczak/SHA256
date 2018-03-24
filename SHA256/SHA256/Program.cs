using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SHA256
{
    class Program
    {
       public static void Main( string[] args)
        {
            Program.IteratedHashAppliedSalt("24", "Aikido123", 56);

        }

        static string IteratedHashAppliedSalt(string uid, string pwd, UInt32 iter)

        {

            const UInt32 MinSize = 1024;
            const UInt32 MaxSize = 32768;

            if (iter < MinSize)
                iter = MinSize;
            if (iter > MaxSize)
                iter = MaxSize;

            const UInt32 Salt_Size = 24;
            byte[] salt = new byte[Salt_Size];
            new RNGCryptoServiceProvider().GetBytes(salt);

            byte[] uidByte = UTF8Encoding.UTF8.GetBytes(uid);
            byte[] pwdByte = UTF8Encoding.UTF8.GetBytes(pwd);
            UInt32 uidLeng = (UInt32)uid.Length;
            UInt32 pwdLeng = (UInt32)pwd.Length;

            byte[] input = new byte[Salt_Size + uidLeng + pwdLeng];
            Array.Copy(uidByte, 0, input, 0, uidLeng);
            Array.Copy(pwdByte, 0, input, 0, pwdLeng);
            Array.Copy(salt, 0, input, 0, Salt_Size);

            HashAlgorithm sha = HashAlgorithm.Create("SHA256");
            byte[] h = sha.ComputeHash(input);

            const UInt32 Uint32_Byte_Count = 32 / 8;
            byte[] buff = new byte[h.Length + h.Length + Salt_Size + Uint32_Byte_Count];
            Array.Copy(salt, 0, buff, h.Length + h.Length, Salt_Size);
            Array.Copy(h, 0, buff, h.Length, h.Length);

            for(UInt32 i=0;i<iter;i++)
            {
                Array.Copy(h, 0, buff, 0, h.Length);
                Array.Copy(BitConverter.GetBytes(i), 0, buff, h.Length + h.Length + Salt_Size, Uint32_Byte_Count);
                h = sha.ComputeHash(buff);
            }

            string result = Convert.ToBase64String(h) + ":" + Convert.ToBase64String(salt);
            return result;


        }
    }
}
