using AuthService.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Middlewares.Extentions
{
    public static class AuthenticationExtention
    {
        public static IServiceCollection AddTokenAuthentication(this IServiceCollection services, IEnumerable<string>? hubsUrls = null)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                AddRequestAuthentication(options);
                if (hubsUrls != null)
                {
                    AddSignalRAuthentication(options, hubsUrls);
                }
            });
            return services;
        }

        private static void AddRequestAuthentication(JwtBearerOptions options)
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Constants.JWT_KEY)),
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                ValidIssuer = Constants.JWT_ISSUER,
                ClockSkew = TimeSpan.Zero
            };
        }
        private static void AddSignalRAuthentication(JwtBearerOptions options, IEnumerable<string> hubsUrls)
        {
            options.Events = new JwtBearerEvents
            {
                OnMessageReceived = context =>
                {
                    var accessToken = context.Request.Query["access_token"];

                    var path = context.HttpContext.Request.Path;
                    if (!string.IsNullOrEmpty(accessToken) && hubsUrls.Any(hubUrl => path.Value.StartsWith(hubUrl)))
                    {
                        context.Token = accessToken;
                    }
                    return Task.CompletedTask;
                }
            };
        }
    }
}
