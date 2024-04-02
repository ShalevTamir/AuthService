using AuthService.Interfaces;
using AuthService.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthService.Services
{
    public class JwtGenerator : ITokenGenerator
    {
        public string GenerateToken()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Constants.JWT_KEY));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var tokenDescription = new SecurityTokenDescriptor()
            {
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddHours(2),
                SigningCredentials = credentials,
                Issuer = Constants.JWT_ISSUER,
            };
            var token = new JwtSecurityTokenHandler().CreateToken(tokenDescription);
            var stringToken = new JwtSecurityTokenHandler().WriteToken(token);
            return stringToken;
        }
    }
}
