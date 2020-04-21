using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace WebApiExample.Controllers
{
    [Route("identity")]
    [Authorize]
    [ApiController]
    public class IdentityController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            var claims = User.Claims.Select(x => $"{x.Type}:{x.Value}");
            return Ok(new
            {
                message = "Hello MVC Core Api!",
                claims = claims.ToArray()
            });
        }
    }
}