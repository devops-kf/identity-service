using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Routing;

namespace IdentityService.Infrastructure.Routing
{
    public class SlugifyParameterTransformer : IOutboundParameterTransformer
    {
        public string TransformOutbound(object value)
        {
            return value == null ? null : Regex.Replace(value.ToString() ?? string.Empty, "([a-z])([A-Z])", "$1-$2").ToLowerInvariant();
        }
    }
}
