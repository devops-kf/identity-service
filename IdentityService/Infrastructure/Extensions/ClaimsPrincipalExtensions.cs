using System;
using System.Security.Claims;

namespace IdentityService.Infrastructure.Extensions
{
    public static class ClaimsPrincipalExtensions
    {
        public static Guid Id(this ClaimsPrincipal claims)
        {
            string userId = claims.FindFirstValue(ClaimTypes.NameIdentifier);

            return userId is null ? Guid.Empty : Guid.Parse(userId);
        }
    }
}
