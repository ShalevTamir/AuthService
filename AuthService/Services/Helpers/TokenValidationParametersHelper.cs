using AuthService.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthService.Services.Helpers
{
    internal static class TokenValidationParametersHelper
    {
        public static TokenValidationParameters BuildParameters(Func<TokenValidationParameters, TokenValidationParameters> callback)
        {
            return callback(GetDefaultParameters());
        }

        public static TokenValidationParameters BuildParameters()
        {
            return GetDefaultParameters();
        }

        private static TokenValidationParameters GetDefaultParameters()
        {
            return new TokenValidationParameters()
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
        
    }
}
