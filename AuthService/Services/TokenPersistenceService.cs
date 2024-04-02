using System;
using System.Collections.Generic;
using System.Text;

namespace AuthService.Services
{
    public class TokenPersistenceService
    {
        // Trace Identifier of the HtttpContext and the corresponding token
        private readonly Dictionary<string, string> _tokens = new Dictionary<string, string>();

        public bool HasToken(string traceIdentifier)
        {
            return _tokens.ContainsKey(traceIdentifier);
        }
        public string GetToken(string traceIdentifier)
        {
            return _tokens[traceIdentifier];
        }

        public void SetToken(string traceIdentifier, string token)
        {
            _tokens[traceIdentifier] = token;
        }

        public void RemoveToken(string traceIdentifier)
        {
            if (HasToken(traceIdentifier))
            {
                _tokens.Remove(traceIdentifier);
            }
        }
    }
}
