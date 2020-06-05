using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecurityService
{
    public class Decrypter
    {
        /// This constant is used to determine the keysize of the encryption algorithm in bits.
        /// We divide this by 8 within the code below to get the equivalent number of bytes.
        private const int Keysize = 128;

        /// This constant determines the number of iterations for the password bytes generation function.
        private const int DerivationIterations = 1000;

        public string Decrypt(string cipherText, string passPhrase)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [16 bytes of IV] + [n bytes of CipherText]
            byte[] cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);

            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            byte[] saltStringBytes = cipherTextBytesWithSaltAndIv
                 .Take(Keysize / 8)
                 .ToArray();

            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            byte[] ivStringBytes = cipherTextBytesWithSaltAndIv
                 .Skip(Keysize / 8)
                 .Take(Keysize / 8)
                 .ToArray();

            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            byte[] cipherTextBytes = cipherTextBytesWithSaltAndIv
                 .Skip((Keysize / 8) * 2)
                 .Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2))
                 .ToArray();

            return GetDecryption(passPhrase, saltStringBytes, ivStringBytes, cipherTextBytes);
        }

        private string GetDecryption(string passPhrase, byte[] saltStringBytes, byte[] ivStringBytes, byte[] cipherTextBytes)
        {
            using Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations);
            byte[] keyBytes = password.GetBytes(Keysize / 8);

            using RijndaelManaged symmetricKey = new RijndaelManaged
            {
                BlockSize = Keysize,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            using ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes);
            using MemoryStream memoryStream = new MemoryStream(cipherTextBytes);
            using CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

            var plainTextBytes = new byte[cipherTextBytes.Length];
            var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
        }
    }
}