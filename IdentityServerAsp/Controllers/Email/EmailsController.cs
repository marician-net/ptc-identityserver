using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Quickstart.UI;
using IdentityServerAsp.Abstractions;
using IdentityServerAsp.Models;
using IdentityServerAsp.ViewModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace IdentityServerAsp.Controllers
{
    public class EmailsController : Microsoft.AspNetCore.Mvc.Controller
    {
        private readonly IUserService _user;
        private readonly UserManager<ApplicationUsers> _userManager;
        private readonly IIdentityEmailSender _emailSender;

        public EmailsController(IUserService user, UserManager<ApplicationUsers> userManager, IIdentityEmailSender emailSender)
        {
            _user = user;
            _userManager = userManager;
            _emailSender = emailSender;
        }


        //Commented out when deployed - this is a HUGE security whole.

        // GET: /<controller>/
        //public async Task<IActionResult> PasswordReset(string email)
        //{
        //    email = email ?? "jeff@nationalcompliance.com";
        //    var model = new ForgotPasswordViewModel() { EmailAddress = email };

        //    var users = _user.GetAllUserByUsernameAndEmail(model.EmailAddress);
        //    var toSendEmail = _user.GetUserByUsernameOrEmail(model.EmailAddress);

        //    var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(users.First());
        //    var encodedToken = Uri.EscapeDataString(emailToken);

        //    var vmodel = await _user.ProcessForgotPassword(model, users);

        //    model.isEmailConfirmed = toSendEmail.EmailConfirmed;
        //    return View(vmodel);
        //}
    }
}
