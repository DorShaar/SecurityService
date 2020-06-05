using SecurityService;
using Xunit;

namespace SecurityServiceTests
{
    public class EncrypterTests
    {
        [Fact]
        public void Encrypt_EncryptedSamePlainTextDifferentPassword_EncryptionResultsNotEqual()
        {
            Encrypter encrypter = new Encrypter();
            string plainText = "This is a secret. \n Please do not read if you are not authorized";
            string passPhrase1 = "Password1";
            string passPhrase2 = "Password2";

            string encryptedString1 = encrypter.Encrypt(plainText, passPhrase1);
            string encryptedString2 = encrypter.Encrypt(plainText, passPhrase2);

            Assert.NotEqual(encryptedString1, encryptedString2);
        }

        [Fact]
        public void Encrypt_EncryptedDifferentPlainTextSamePassword_EncryptionResultsNotEqual()
        {
            Encrypter encrypter = new Encrypter();
            string plainText1 = "This is a secret. \n Please do not read if you are not authorized";
            string plainText2 = "This is a secret. \n\t Please do not read if you are not authorized";
            string passPhrase = "Password";

            string encryptedString1 = encrypter.Encrypt(plainText1, passPhrase);
            string encryptedString2 = encrypter.Encrypt(plainText2, passPhrase);

            Assert.NotEqual(encryptedString1, encryptedString2);
        }
    }
}