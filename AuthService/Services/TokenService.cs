using AuthService.Interfaces;
using AuthService.Models;
using AuthService.Services.Helpers;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Services
{
    public class TokenService : ITokenService
    {
        private const uint REFRESH_TOKEN_SIZE = 32;
        public string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Constants.JWT_KEY));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var tokenOptions = new JwtSecurityToken(
                issuer: Constants.JWT_ISSUER,
                signingCredentials: credentials,
                expires: DateTime.UtcNow.AddSeconds(15),
                claims: claims
                );
            var stringToken = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
            return stringToken;
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[REFRESH_TOKEN_SIZE];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var parameters = TokenValidationParametersHelper.BuildParameters(defaultParameters =>
            {
                defaultParameters.ValidateLifetime = false;
                return defaultParameters;
            });

            var tokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principals = tokenHandler.ValidateToken(token, parameters, out SecurityToken validatedToken);
            if (validatedToken == null)
            {
                throw new SecurityTokenException("Invalid token");
            }
            return principals;
        }
    }
}
