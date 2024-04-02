using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace AuthService.Services.DelegatingHandlers
{
    internal class TokenAdditionHandler : DelegatingHandler
    {
        private TokenPersistenceService _tokenPersistenceService;
        private IHttpContextAccessor _httpContextAccessor;
        public TokenAdditionHandler(TokenPersistenceService tokenPersistenceService, IHttpContextAccessor httpContextAccessor)
        {
            _tokenPersistenceService = tokenPersistenceService;
            _httpContextAccessor = httpContextAccessor;
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (TryGetTraceIdentifier(out string? identifier) 
                && _tokenPersistenceService.HasToken(identifier))
            {
                request.Headers.Authorization =
                    new AuthenticationHeaderValue("Bearer",
                    _tokenPersistenceService.GetToken(identifier)
                    );
            }
            return await base.SendAsync(request, cancellationToken);
        }

        private bool TryGetTraceIdentifier(out string? identifier)
        {
            identifier = null;
            if (_httpContextAccessor.HttpContext != null)
            {
                identifier = _httpContextAccessor.HttpContext.TraceIdentifier;
                return true;
            }
            return false;
        }
    }
}
