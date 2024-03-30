using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.Text.Json;
using System.Security.Claims;
using Newtonsoft.Json.Linq;
using AuthService.Models;

namespace AuthService.Middlewares
{
    internal class TokenMessageMiddleware
    {
        private readonly RequestDelegate _next;

        public TokenMessageMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            TryExtractAuthorizationToken(context.Request, out var token);
            await _next(context);
            await AddTokenMessage(context, token);
        }

        private async Task AddTokenMessage(HttpContext context, string? token)
        {
            if (context.Response.StatusCode == StatusCodes.Status401Unauthorized)
            {
                if (string.IsNullOrEmpty(token))
                {
                    await context.Response.WriteAsync("Missing token");
                    return;
                }
                var validationParameters = new TokenValidationParameters()
                {
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Constants.JWT_KEY)),
                    ValidateLifetime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateIssuerSigningKey = false,
                    ClockSkew = TimeSpan.Zero
                };
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationResult = await tokenHandler.ValidateTokenAsync(token, validationParameters);

                if (validationResult.Exception is SecurityTokenExpiredException)
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsync("Token has expired");
                    return;
                }
                await context.Response.WriteAsync("Invalid token");
            }
        }

        private bool TryExtractAuthorizationToken(HttpRequest request, out string? token)
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
