using System;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;

namespace Jwt.Models.Jwt
{
    public class JwtTokenHelper
    {
        IConfiguration Configuration;
        JwtTokenOptions _tokenOptions;
        DateTime _tokenExpiration;

        public JwtTokenHelper(IConfiguration configuration){
            Configuration = configuration;
            _tokenOptions = Configuration.GetSection("TokenOptions").Get<JwtTokenOptions>();
            _tokenExpiration = DateTime.Now.AddMinutes(_tokenOptions.TokenExpiration);
        }

        public JwtToken CreateToken(User user, string[] roles)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenOptions.SecurityKey));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            var securityToken = CreateJwtSecurityToken(_tokenOptions,user,signingCredentials,roles);
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var token = jwtSecurityTokenHandler.WriteToken(securityToken);
            return new JwtToken{
                Token = token,
                Expiration = _tokenExpiration
            };
        }

        private JwtSecurityToken CreateJwtSecurityToken(JwtTokenOptions tokenOptions, User user, SigningCredentials signingCredentials, string[] roles){
            var jwt = new JwtSecurityToken(
                    issuer: tokenOptions.Issuer,
                    audience: tokenOptions.Audience,
                    expires: _tokenExpiration,
                    notBefore: DateTime.Now,
                    claims: SetClaims(user, roles),
                    signingCredentials: signingCredentials
                );
            return jwt;
        }

        private IEnumerable<Claim> SetClaims(User user, string[] roles)
        {
            var claims = new List<Claim>();
            claims.Add(new Claim(JwtRegisteredClaimNames.Email,user.Email));
            claims.Add(new Claim(ClaimTypes.NameIdentifier,user.Username));
            roles.ToList().ForEach(role => claims.Add(new Claim(ClaimTypes.Role,role)));
            return claims;
        }
    }
}