using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace IdentityService.Security
{
    // TODO (fivkovic) [8]: Rework this
    public class PublicSecurityKeyProvider
    {
        public AsymmetricSecurityKey PublicKey { get; }

        public PublicSecurityKeyProvider()
        {
            string keyPath = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? string.Empty, "Security/Keys/public_key.pem");
            string pemKey = File.ReadAllText(keyPath);
            PublicKey = CreatePublicKey(pemKey);
        }

        public RsaSecurityKey CreatePublicKey(string pemKey)
        {
            RSA rsa = RSA.Create();
            rsa.ImportFromPem(pemKey);

            return new RsaSecurityKey(rsa);
        }
    }
}
