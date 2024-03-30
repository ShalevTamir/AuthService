using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthService.Middlewares.Extentions
{
    public static class TokenMessageMiddlewareExtentions
    {
        public static IApplicationBuilder UseTokenMessage(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<TokenMessageMiddleware>();
        }
    }
}
