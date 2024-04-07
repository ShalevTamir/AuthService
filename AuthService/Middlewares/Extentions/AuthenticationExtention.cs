using AuthService.Models;
using AuthService.Services;
using AuthService.Services.DelegatingHandlers;
using AuthService.Services.Helpers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
            services.AddSingleton<TokenPersistenceService>();
            services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddTransient<TokenAdditionHandler>();
            services.AddHttpClient(Constants.HTTP_CLIENT_NAME).AddHttpMessageHandler<TokenAdditionHandler>();            

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                AddRequestAuthentication(options, TokenValidationParametersHelper.BuildParameters());
                if (hubsUrls != null)
                {
                    AddSignalRAuthentication(options, hubsUrls);
                }
            });
            return services;
        }

        private static void AddRequestAuthentication(JwtBearerOptions options, TokenValidationParameters parameters)
        {
            options.TokenValidationParameters = parameters;
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
