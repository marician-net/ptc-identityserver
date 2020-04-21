using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServerAsp;
using IdentityServerAsp.Abstractions;
using IdentityServerAsp.Models;
using IdentityServerAsp.ViewModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.Controllers.Admin
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {

        private readonly IUserService _user;
        private readonly SignInManager<ApplicationUsers> _signInManager;

        public  AdminController(IUserService user, SignInManager<ApplicationUsers> signInManager)
        {
            _user= user;
            _signInManager = signInManager;
        }
        public IActionResult Index()
        {

            return Redirect("~/Admin/Users");
        }

        public IActionResult Users()
        {
            return View(_user.GetUsers(1));
        }
        [HttpPost]
        public ActionResult Users(int currentPageIndex)
        {
            return View(_user.GetUsers(currentPageIndex));
        }

        public IActionResult UserDetail(string id)
        {

            ApplicationUsers applicationUsers = _user.GetUserById(id);
            return View(applicationUsers);
        }

        [HttpPost]
        public async Task<IActionResult> UserDetail(ApplicationUsers applicationUsers)
        {
            await _user.AddorUpdate(applicationUsers,null);
            return View("UserDetail", applicationUsers);
        }

        public IActionResult Clients()
        {
            return View();
        }

        public async Task<IActionResult> Logout()
        {

            await _signInManager.SignOutAsync();
            return Redirect("/Home/Index");
        }
    }
}