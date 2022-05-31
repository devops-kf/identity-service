using IdentityService.Configuration;
using Microsoft.AspNetCore.Http;

namespace IdentityService.Infrastructure.Extensions
{
    public static class CookieExtensions
    {
        public static string RefreshToken(this IRequestCookieCollection cookies)
        {
            return cookies[RefreshTokenConfiguration.CookieName];
        }

        public static void DeleteRefreshToken(this IResponseCookies cookies)
        {
            cookies.Delete(RefreshTokenConfiguration.CookieName);
        }

        public static void AppendRefreshToken(this IResponseCookies cookies, string refreshToken)
        {
            cookies.Append(RefreshTokenConfiguration.CookieName, refreshToken, new CookieOptions
            {
                IsEssential = true,
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            });
        }
    }
}
