using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApplication1.Models;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        public static User us = new User();
        public static UserLog log = new UserLog();
        private readonly JWTContext _context;
        private readonly UserViewModel _personService;

        //public ValuesController()
        //{
            
        //}
        public ValuesController(JWTContext context, UserViewModel personService)
        {
            _context = context;
            _personService = personService;
        }
        [HttpPost("Register")]
        public async Task<ActionResult<User>> Register(User request)
        {
            var log = _context.Users.Where(x => x.Username.Equals(request.Username)).FirstOrDefault();

            var result = from s in _context.Users
                         where s.Username.Equals(request.Username)
                         select s;
              if(result != null)
                {
                    _context.Users.Add(request);
                    await _context.SaveChangesAsync();
                    return Json(new { message="Hello" });
                    return new JsonResult("Signup Sucess");

                }
           
              else
            //if (result != null)
                return BadRequest(new { message = "SIgnup Failed '{ex}'" });
           // return Ok("Not working");
           
            
        }
        [HttpPost("Login")]
        public async Task<ActionResult<User>> Registered(UserLog request)
        {
            //    var log = _context.Users.Where(x => x.Username.Equals(request.UserName) && x.Password.Equals(request.Password)).FirstOrDefault();

            //    if (log == null)
            //    {

            //        return new JsonResult(new { status = 401, isSuccess = false, message = "Invalid User", });
            //    }
            //    else
            //    {

            //        string token = CreateToken(request);
            //        return new JsonResult(token);
            //        //return Ok(new { status = 200, isSuccess = true, message = "User Login successfully", UserDetails = log });
            //    }
            //}

            try
            {
               // await _personService.Login(request);
                return Ok(await _personService.Login(request));
            }
            catch (Exception ex)
            {
                return BadRequest($"Bad'{ex}'");
            }

        }



        //    var result = from s in _context.Users
        //                 where s.Username.Equals(request.UserName)
        //                 select s;
        //    int i=1, j=1;
        //    string st = " ";
        //    foreach (var sc in result)
        //    {
        //        if (result != null)
        //        {
        //            var result1 = from s1 in _context.Users
        //                          where s1.Password.Equals(request.Password)
        //                          select s1;
        //            foreach (var f in result1)
        //            {
        //                if (result1 != null)//result1.ToString().Contains(request.Password))
        //                {
        //                    string token = CreateToken(request);
        //                    i = j = 1;
        //                    return Ok("Login Sucessful \n" + token);
        //                }
        //                else if(result1 == null)
        //                {
        //                    j = 0;
        //                    st = "No Password";
        //                    return BadRequest("No Password");

        //                }
        //            }
        //        }
        //        else if (result == null)
        //        {
        //            st = "No Username";
        //            i = 0;
        //            return BadRequest("No Username");


        //        }
        //    }
        //    return BadRequest(st);
        //}
        //private string CreateToken(UserLog usr)
        //{
        //    List<Claim> claims = new List<Claim>
        //    {
        //        new Claim(ClaimTypes.Name, (usr.UserName)),
        //    };
        //    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secretKey!753159"));
        //    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
        //    var token = new JwtSecurityToken(
        //        claims: claims,
        //        expires: DateTime.Now.AddDays(1),
        //        signingCredentials: creds);
        //    var jwt = new JwtSecurityTokenHandler().WriteToken(token);
        //    return jwt;
        //}
    }
}
