namespace IdentityService.Configuration
{
    public class AccessTokenConfiguration
    {
        public double LifetimeInMinutes { get; set; }
        public string Purpose { get; } = "access";
    }
}
