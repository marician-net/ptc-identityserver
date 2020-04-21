using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ClientExample.Pages
{
    public class BasePageModel: PageModel
    {
        public ActionResult OnPostLogin()
        {
            return Challenge(new AuthenticationProperties()
            {
                RedirectUri = "/About"
            }, "oidc");   
        }

        public ActionResult OnPostLogout()
        {
            return SignOut(new AuthenticationProperties()
            {
                RedirectUri = "/Home/Index"
            },"Cookies", "oidc");        
        }
    }
}
