namespace IdentityService.Configuration
{
    public class JwtConfiguration
    {
        public string Key { get; set; }
        public string Issuer { get; set; }
        public AccessTokenConfiguration AccessToken { get; set; }
        public RefreshTokenConfiguration RefreshToken { get; set; }
    }
}
