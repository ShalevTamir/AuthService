using System;
using System.Collections.Generic;
using System.Text;

namespace AuthService.Interfaces
{
    public interface ITokenGenerator
    {
        public string GenerateToken();
    }
}
