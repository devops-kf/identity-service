namespace IdentityService.Configuration
{
    public class RefreshTokenConfiguration
    {
        public string Purpose { get; } = "refresh";
        public static string CookieName { get; } = "refresh_token";
        public double LifetimeInDays { get; set; }
    }
}
