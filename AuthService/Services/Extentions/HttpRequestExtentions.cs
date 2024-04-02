using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AuthService.Services.Extentions
{
    internal static class HttpRequestExtentions
    {
        internal static bool TryExtractAuthorizationToken(this HttpRequest request, out string? token)
        {
            token = null;
            if (!request.Headers.ContainsKey("Authorization"))
            {
                return false;
            }

            var authorizationHeader = request.Headers["Authorization"].FirstOrDefault();
            if (authorizationHeader?.StartsWith("Bearer ") != true)
            {
                return false;
            }

            token = authorizationHeader.Substring("Bearer ".Length).Trim();
            return true;
        }
    }
}
