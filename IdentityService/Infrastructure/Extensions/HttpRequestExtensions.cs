using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace IdentityService.Infrastructure.Extensions
{
    public static class HttpRequestExtensions
    {
        public static string IpAddress(this HttpRequest request)
        {
            return request.Headers.ContainsKey("X-Forwarded-For") ?
                   request.Headers["X-Forwarded-For"].ToString() :
                   request.HttpContext.Connection.RemoteIpAddress?.MapToIPv4().ToString();
        }

        public static string UserAgent(this HttpRequest request)
        {
            return request.Headers[HeaderNames.UserAgent].ToString();
        }
    }
}
