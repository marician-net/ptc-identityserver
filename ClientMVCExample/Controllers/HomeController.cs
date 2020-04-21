using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using ClientMVCExample.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ClientMVCExample.Controllers
{
    public class HomeController : Controller
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly OpenIdConnectPostConfigureOptions _openIdConnectPostConfigureOptions;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IOptionsMonitorCache<OpenIdConnectOptions> _openIdConnectOptionsMonitorCache;
        private string azureName = "azure";
        private string oktaName = "okta";
        private List<AuthenticationScheme> _schemaList = new List<AuthenticationScheme>();

        public HomeController(IServiceProvider serviceProvider, OpenIdConnectPostConfigureOptions _openIdConnectPostConfigureOptions, 
            IAuthenticationSchemeProvider schemeProvider, IOptionsMonitorCache<OpenIdConnectOptions> openIdConnectOptionsMonitorCache)
        {
            _serviceProvider = serviceProvider;
            this._openIdConnectPostConfigureOptions = _openIdConnectPostConfigureOptions;
            _schemeProvider = schemeProvider;
            _openIdConnectOptionsMonitorCache = openIdConnectOptionsMonitorCache;

            _schemaList = _schemeProvider.GetAllSchemesAsync().GetAwaiter().GetResult().ToList();

            if (_schemaList.All(x => x.Name != azureName))
            {
                _schemeProvider.AddScheme(new AuthenticationScheme(azureName, azureName, typeof(OpenIdConnectHandler)));

                var openIdOptions = new OpenIdConnectOptions()
                {
                    SignInScheme = "Cookies",
                    Authority = "https://login.microsoftonline.com/a5c460b6-6f06-464c-a3ce-003d212b0155",
                    RequireHttpsMetadata = true,
                    CallbackPath = "/signin-oidc",
                    ClientId = "52b606c5-e5e9-456e-ab2a-cf7b800ce523",
                    ClientSecret = "3!5F$=l.Wj$!n=#}#83L%^I/^",
                    ResponseType = "code id_token",
                    SignedOutCallbackPath = "/signout-oidc",
                    SignedOutRedirectUri = "/home/index",
                    SaveTokens = true,
                };

                _openIdConnectPostConfigureOptions?.PostConfigure(azureName, openIdOptions);
                _openIdConnectOptionsMonitorCache.TryAdd(azureName, openIdOptions);
            }

            if (_schemaList.All(x => x.Name != oktaName))
            {
                _schemeProvider.AddScheme(new AuthenticationScheme(oktaName, oktaName, typeof(OpenIdConnectHandler)));

                var openIdOptionsOkta = new OpenIdConnectOptions()
                {
                    SignInScheme = "Cookies",
                    Authority = "https://contractlogix.oktapreview.com",
                    RequireHttpsMetadata = true,
                    CallbackPath = "/signin-oidc-okta",
                    ClientId = "0oajrwq9w8FXS9Tml0h7",
                    ClientSecret = "tu8KMjw5NHdfB3i4FPqmlnZgH86Tmavs_uy30FVM",
                    ResponseType = "code id_token",
                    SignedOutCallbackPath = "/signout-oidc-okta",
                    SignedOutRedirectUri = "/home/index",
                    SaveTokens = true,
                    Events = new OpenIdConnectEvents()
                    {
                        OnTokenValidated = OnTokenValidated,
                        OnAuthenticationFailed = OnAuthenticationFailed
                    }
                };

                _openIdConnectPostConfigureOptions?.PostConfigure(oktaName, openIdOptionsOkta);
                _openIdConnectOptionsMonitorCache.TryAdd(oktaName, openIdOptionsOkta);
            }
        }

        private async Task OnAuthenticationFailed(AuthenticationFailedContext arg)
        {
            Response.Redirect("/Home/Error");
        }

        private async Task OnTokenValidated(TokenValidatedContext arg)
        {
            arg.Fail("Not a valid user.");
        }


        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult LoginAzure()
        {
            return Challenge(new AuthenticationProperties()
            {
                RedirectUri = "/Home/Index"
            }, azureName);        
        }

        public IActionResult LoginOkta()
        {
            return Challenge(new AuthenticationProperties()
            {
                RedirectUri = "/Home/Index"
            }, oktaName);        
        }

        public IActionResult Logout()
        {
            return LogoutAll();
        }

        private IActionResult LogoutAll()
        {
            var schemas = _schemaList.Select(x => x.Name).ToList();
            schemas.Add("Cookies");
            return SignOut(new AuthenticationProperties(), schemas.ToArray());
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
