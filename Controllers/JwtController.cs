using Jwt.Models;
using Jwt.Models.Jwt;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace jwt.Controllers
{
    public class JwtController:Controller
    {
        IConfiguration Configuration;
        JwtTokenHelper tokenHelper;
        public JwtController(IConfiguration configuration){
            Configuration = configuration;
            tokenHelper = new JwtTokenHelper(Configuration);
        }

        [HttpPost("Jwt/CreateToken")]
        public IActionResult CreateToken([FromBody] User user){
            string[] roles = {"admin","user"};
            var token = tokenHelper.CreateToken(user,roles);
            return Ok(token);
        }
    }
}