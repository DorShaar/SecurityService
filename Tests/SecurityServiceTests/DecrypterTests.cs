using SecurityService;
using Xunit;

namespace SecurityServiceTests
{
    public class DecrypterTests
    {
        [Fact]
        public void Decrypt_EncryptedSamePlainTextSamePassword_SameEncryptionResults()
        {
            Decrypter decrypter = new Decrypter();
            string cypherText1 = "bJ3jvVY7JuLAXaSa+YOyX+LCJwf/vqOoNYqTtfXrb1MuIOCXBBWjrXEURB/mEA46QwxX+yflecDqksWFzIdiuk1V2CGToV0gNOPrxYpu9n+1aeBhJuHQ163B0Lvv8n8+yNkTAsF/+X0nNVi00KLBwQ==";
            string cypherText2 = "sGUsDTz8pN6EH9GP46fX07ZdPKbDhajJxuvYH8IRCPsFbx6wbAlyMuOMUOrzB7zCWs8vx0UFs399RV9k2RBk2zYVHM2MKVzuw4X7SzWoO0ufY47i2hFyB4cpf9PMCADv83Q5cB+TK+UajCaTd/6W8Q==";
            string passPhrase = "Password";

            string decryptedString1 = decrypter.Decrypt(cypherText1, passPhrase);
            string decryptedString2 = decrypter.Decrypt(cypherText2, passPhrase);

            string plainText = "This is a secret. \n Please do not read if you are not authorized";

            Assert.Equal(plainText, decryptedString1);
            Assert.Equal(plainText, decryptedString2);
        }

        [Fact]
        public void Decrypt_EncryptWithWrongPassword_WrongResult()
        {
            Decrypter decrypter = new Decrypter();
            string cypherText = "bJ3jvVY7JuLAXaSa+YOyX+LCJwf/vqOoNYqTtfXrb1MuIOCXBBWjrXEURB/mEA46QwxX+yflecDqksWFzIdiuk1V2CGToV0gNOPrxYpu9n+1aeBhJuHQ163B0Lvv8n8+yNkTAsF/+X0nNVi00KLBwQ==";
            string wrongPassPhrase = "Password111";
            string plainText = "This is a secret. \n Please do not read if you are not authorized";

            Assert.NotEqual(plainText, decrypter.Decrypt(cypherText, wrongPassPhrase));
        }
    }
}