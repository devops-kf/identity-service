using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using Microsoft.OpenApi.Models;

namespace IdentityService.Infrastructure.Filters
{
    public class SwaggerPreSerializeFilter
    {
        public static readonly Action<OpenApiDocument, HttpRequest> Filter = (swagger, httpReq) =>
        {
            if (httpReq.Headers.ContainsKey("X-Forwarded-Host"))
            {
                var scheme = httpReq.Scheme;
                var host = httpReq.Headers["X-Forwarded-Host"];
                var port = httpReq.Headers["X-Forwarded-Port"];
                var prefix = httpReq.Headers["X-Forwarded-Prefix"];
                var path = httpReq.PathBase;
                var serverUrl = $"{scheme}://{host}:{port}{prefix}/{path}";

                swagger.Servers = new List<OpenApiServer> { new OpenApiServer { Url = serverUrl } };
            }
        };
    }
}
