using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Services;
using IdentityServerAsp.Abstractions;
using IdentityServerAsp.Models;
using IdentityServerAsp.ViewModel;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerAsp.Controllers
{
    [Route("api/users")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class UserAPIController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IIdentityServerInteractionService _interaction;

        public UserAPIController(IUserService userService, IIdentityServerInteractionService interaction)
        {
            _userService = userService;
            _interaction = interaction;
        }

        [HttpPost]
        public async Task<dynamic> Post(UserViewModel userViewModel)
        {
            string confirmedLoginUri = GetOriginUri() + "/Login.aspx";
            var result=  await _userService.AddorUpdate(userViewModel,confirmedLoginUri);
            return  Ok(result);
        }

        private string GetOriginUri()
        {
            string confirmedLoginUri = null;
            if (Request.Headers.ContainsKey("Origin"))
            {
                var requester = Request.Headers["Origin"];
                confirmedLoginUri = new Uri(requester).GetLeftPart(UriPartial.Authority);
            }

            return confirmedLoginUri;
        }

        [HttpPost]
        [Route("delete")]
        public async Task<IActionResult> DeleteUsers([FromBody]UserApiViewModel model)
        {
            var users =  _userService.GetUserByName(model.userName);
            if (users == null) return NotFound();
            await _userService.DeleteUsers(users);
            return Ok();
        }

        [HttpPost]
        [Route("revive")]
        public async Task<IActionResult> ResumeUsers([FromBody]UserApiViewModel model)
        {
            var users = _userService.GetUserByName(model.userName);
            if (users == null) return NotFound();
            await _userService.ResumeUsers(users);
            return Ok();
        }

        [HttpPost]
        [Route("sendconfirmationemail")]
        public async Task<IActionResult> SendConfirmationEmail([FromBody]UserApiViewModel model)
        {
            var loginUri = GetOriginUri();
            var users = _userService.GetUserByName(model.userName);
            if (users == null) return NotFound();
            await _userService.SendEmail(users,loginUri);
            return Ok();
        }

        public class UserApiViewModel
        {
            public string userName { get; set; }
        }
    }
}