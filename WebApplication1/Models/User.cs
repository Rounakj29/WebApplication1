using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WebApplication1.Models
{
    public partial class User
    {
        [Key]
        public string Username { get; set; } 
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
    public class UserViewModel
    {
        private readonly JWTContext _context;

        public UserViewModel(JWTContext context)
        {
            _context = context;
        }
        public async Task<JsonResult> Login(UserLog request)
        {
            
        var log = _context.Users.Where(x => x.Username.Equals(request.UserName) && x.Password.Equals(request.Password)).FirstOrDefault();

            if (log == null)
            {

                return new JsonResult(new { status = 401, isSuccess = false, message = "Invalid User", });
            }
            else
            {

                string token = CreateToken(request);
                return new JsonResult(token);
                //return Ok(new { status = 200, isSuccess = true, message = "User Login successfully", UserDetails = log });
            }
        }
        private string CreateToken(UserLog usr)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, (usr.UserName)),
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secretKey!753159"));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
    }
}
