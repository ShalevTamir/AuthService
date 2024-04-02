using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthService.Middlewares.Extentions
{
    public static class TokenMiddlewaresExtentions
    {
        public static IApplicationBuilder UseTokenPersistence(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<TokenPersistenceMiddleware>();
        }
        public static IApplicationBuilder UseTokenMessage(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<TokenMessageMiddleware>();
        }

        public static IApplicationBuilder UseTokenMiddlewares(this IApplicationBuilder builder)
        {
            return builder
                .UseTokenPersistence()
                .UseTokenMessage();
        }
    }
}
