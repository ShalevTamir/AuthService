using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace AuthService.Interfaces
{
    public interface ITokenService
    {
        public string GenerateAccessToken(IEnumerable<Claim> claims);
        public string GenerateRefreshToken();
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
