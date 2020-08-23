using System;

namespace Jwt.Models.Jwt
{
    public class JwtToken
    {
        public string Token { get; set; }
        public DateTime Expiration { get; set; }
    }
}