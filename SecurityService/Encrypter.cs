using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecurityService
{
    public class Encrypter
    {
        /// This constant is used to determine the keysize of the encryption algorithm in bits.
        /// We divide this by 8 within the code below to get the equivalent number of bytes.
        private const int Keysize = 128;

        /// This constant determines the number of iterations for the password bytes generation function.
        private const int DerivationIterations = 1000;

        public string Encrypt(string plainText, string passPhrase)
        {
            /// Salt and IV are randomly generated each time, but is preprended to encrypted cipher text
            /// so that the same Salt and IV values can be used when decrypting.
            byte[] ivStringBytes = Generate256BitsOfRandomEntropy();
            byte[] saltStringBytes = Generate256BitsOfRandomEntropy();

            using ICryptoTransform encryptor = CreateCryptographicTransformer(passPhrase, saltStringBytes, ivStringBytes);

            using var memoryStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
            cryptoStream.FlushFinalBlock();

            // Create the final bytes as a concatenation of the random salt bytes, the random iv bytes and the cipher bytes.
            var cipherTextBytes = saltStringBytes;
            cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
            cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
            return Convert.ToBase64String(cipherTextBytes);
        }

        private byte[] Generate256BitsOfRandomEntropy()
        {
            byte[] randomBytes = new byte[Keysize / 8]; // 16 Bytes will give us 128 bits, 32B => 256 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }

            return randomBytes;
        }

        private ICryptoTransform CreateCryptographicTransformer(string passPhrase, byte[] saltStringBytes, byte[] ivStringBytes)
        {
            using var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations);
            var keyBytes = password.GetBytes(Keysize / 8);
            using var symmetricKey = new RijndaelManaged
            {
                BlockSize = Keysize,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            return symmetricKey.CreateEncryptor(keyBytes, ivStringBytes);
        }
    }
}