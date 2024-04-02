using AuthService.Services;
using AuthService.Services.Extentions;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Middlewares
{
    internal class TokenPersistenceMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly TokenPersistenceService _tokenPersistence;
        public TokenPersistenceMiddleware(RequestDelegate next, TokenPersistenceService tokenPersistenceService)
        {
            _next = next;
            _tokenPersistence = tokenPersistenceService;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.Request.TryExtractAuthorizationToken(out var token))
            {
                _tokenPersistence.SetToken(context.TraceIdentifier, token);
            }
            await _next(context);
            _tokenPersistence.RemoveToken(context.TraceIdentifier);
        }
    }
}
