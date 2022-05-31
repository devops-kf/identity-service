using System.IO;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace IdentityService.Security
{
    // TODO (fivkovic) [8]: Rework this
    public class AsymmetricSecurityKeyProvider : PublicSecurityKeyProvider
    {
        public AsymmetricSecurityKey PrivateKey { get; }

        public AsymmetricSecurityKeyProvider()
        {
            string privateKeyPem = File.ReadAllText("Security/Keys/private_key.pem");
            PrivateKey = CreatePrivateKey(privateKeyPem);
        }

        public RsaSecurityKey CreatePrivateKey(string privateKeyPem)
        {
            RSA rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);

            return new RsaSecurityKey(rsa);
        }
    }
}
