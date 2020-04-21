// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Quickstart.UI;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Test;
using IdentityServerAsp.Controller.Account;
using IdentityServerAsp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Rewrite.Internal.UrlActions;
using IdentityServerAsp.ViewModel;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure;
using System.Net.Mail;
using IdentityServerAsp.Abstractions;
using System.Text.Encodings.Web;
using System.IO;
using System.Net;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Claims;
using IdentityServerAsp;
using IdentityServerAsp.Data;
using IdentityServerAsp.Helpers;
using MimeKit;
using Microsoft.AspNetCore.Hosting;
using IdentityServerAsp.Services;
using Microsoft.Extensions.Configuration;

namespace IdentityServer4.Quickstart.UI
{
    /// <summary>
    /// This sample controller implements a typical login/logout/provision workflow for local and external accounts.
    /// The login service encapsulates the interactions with the user data store. This data store is in-memory only and cannot be used for production!
    /// The interaction service provides a way for the UI to communicate with identityserver for validation and context retrieval
    /// </summary>
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUsers> _userManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly SignInManager<ApplicationUsers> _signInManager;
        private readonly IConfiguration _config;
        private readonly ApplicationDbContext _context;
        private readonly IIdentityEmailSender _emailSender;
        private readonly IUserService _user;
        private readonly IRazorViewToEmailRenderer _emailRenderer;


        public AccountController(
            IIdentityServerInteractionService interaction,
            IIdentityEmailSender emailSender,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            IUserService user,
            IRazorViewToEmailRenderer emailRenderer,
            UserManager<ApplicationUsers> userManager,
            SignInManager<ApplicationUsers> signInManager,
            IConfiguration config,
            ApplicationDbContext context)
        {
            // if the TestUserStore is not in DI, then we'll just use the global users collection
            // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)
            _userManager = userManager;
            _emailSender = emailSender;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _user = user;
            _emailRenderer = emailRenderer;
            _signInManager = signInManager;
            _config = config;
            _context = context;
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {            
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);
            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            if (button != "login")
            {
                var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
                if (context != null)
                {
                    await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);
                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                if (User?.Identity.IsAuthenticated == true)
                {
                    // delete local authentication cookie
                    await _signInManager.SignOutAsync();
                    // raise the logout event
                    await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
                }

                var user = await _userManager.FindByNameAsync(model.Username);
                if (user == null)
                {
                    await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials"));
                    ModelState.AddModelError("", AccountOptions.InvalidCredentialsErrorMessage);
                    return View(await BuildLoginViewModelAsync(model));
                }
                var isLockedOut = await _userManager.IsLockedOutAsync(user);
                var isConfirmed = await _userManager.IsEmailConfirmedAsync(user);
                var result = await _userManager.CheckPasswordAsync(user, model.Password);
                if (user != null && await _userManager.CheckPasswordAsync(user, model.Password) && !isLockedOut && isConfirmed)
                {
                    await _events.RaiseAsync(
                        new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName));

                    var signInResult = await _signInManager.PasswordSignInAsync(model.Username,model.Password,model.RememberLogin,true);

                    if (_interaction.IsValidReturnUrl(model.ReturnUrl)
                            || Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }

                    return Redirect("~/");
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials"));
                ModelState.AddModelError("", AccountOptions.InvalidCredentialsErrorMessage);
            }

            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        [HttpPost]
        public async Task<IActionResult> Authenticate([FromBody] AuthenticateModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserNameOrEmailAddress);
            if (user == null)
            {
                return BadRequest(new LoginException("Invalid username or password.", HttpStatusCode.Unauthorized.ToString()));
            }
            var isLockedOut = await _userManager.IsLockedOutAsync(user);
            var isConfirmed = await _userManager.IsEmailConfirmedAsync(user);
            var result = await _userManager.CheckPasswordAsync(user, model.Password);
            if (await _userManager.CheckPasswordAsync(user, model.Password) && !isLockedOut &&
                isConfirmed)
            {
                await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName));
                var signInResult = await _signInManager.PasswordSignInAsync(model.UserNameOrEmailAddress, model.Password, false, true);
                var claimsPrinciple = await _signInManager.CreateUserPrincipalAsync(user);
                var accessToken = await CreateAccessToken(claimsPrinciple.Claims.ToList(), user);
                //var refreshToken = CreateRefreshToken(await CreateJwtClaims(loginResult.Identity, loginResult.User, tokenType: TokenType.RefreshToken));

                return Ok(new AuthenticateResultModel()
                {
                    AccessToken = accessToken,
                    ExpireInSeconds = (int)3600, //1hr
                    //RefreshToken = refreshToken,
                    //EncryptedAccessToken = GetEncryptedAccessToken(accessToken),
                    UserId = user.Id,
                    //ReturnUrl = returnUrl
                });
            }

            return BadRequest(new LoginException("Invalid username or password.",HttpStatusCode.Unauthorized.ToString()));

        }

        private async Task<string> CreateAccessToken(List<Claim> claims, ApplicationUsers user)
        {
            var now = DateTime.UtcNow;

            claims.Add(new Claim("ptconlineId", user.ptcOnlineId ?? ""));
            claims.Add(new Claim(ClaimTypes.Name, user.ptcOnlineId ?? ""));

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _config.GetValue<string>("IdentityServer:Authority"),
                audience: Startup.Authority,
                claims: claims,
                notBefore: now,
                signingCredentials: Startup.SigningCredentials,
                expires:  DateTime.Now.AddDays(90)
            );

            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }


        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        [HttpGet]
        public IActionResult ConfirmEmailError()
        {
            return View();
        }

        [HttpGet()]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string username, [FromQuery] string code, [FromQuery] string redirectUri)
        {
            var user = await _userManager.FindByIdAsync(username);
            ViewBag.MultipleAccounts = false;

            if (_user.GetAllUserByUsernameAndEmail(username).Count > 1)
            {
                ViewBag.MultipleAccounts = true;
            }
            ViewBag.UserId = username;
            ViewBag.RedirectUri = redirectUri;
            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (!result.Succeeded)
            {
                return RedirectToAction("ConfirmEmailError");
            }

            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ConfirmEmail([FromForm] UserPasswordCheckViewModel model)
        {

            var user = await _userManager.FindByIdAsync(model.UserId);
            ViewBag.UserId = user.Id;
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (ModelState.IsValid)
            {
                if (!string.IsNullOrEmpty(user.PasswordHash))
                {
                    await _userManager.RemovePasswordAsync(user);
                }

                var addPasswordResult = await _userManager.AddPasswordAsync(user, model.Password);
                if (!addPasswordResult.Succeeded && addPasswordResult.Errors.Any())
                {
                    foreach (var error in addPasswordResult.Errors)
                    {
                        ModelState.AddModelError("Password", error.Description);
                    }
                    return View(model);
                }

                if (model.ResetAllUsernames)
                {
                    var users = _user.GetAllUserByUsernameAndEmail(user.Email);
                    foreach (var otherUser in users)
                    {
                        if (!string.IsNullOrEmpty(otherUser.PasswordHash))
                        {
                            await _userManager.RemovePasswordAsync(otherUser);
                        }
                        await _userManager.AddPasswordAsync(otherUser, model.Password);
                    }
                }

            }
            else
                return View(model);

            await _signInManager.RefreshSignInAsync(user);
            return RedirectToAction("ConfirmedEmail", "Account", new { RedirectUri = model.RedirectUri});
        }

        [HttpGet()]
        public IActionResult ConfirmedEmail(string RedirectUri)
        {
            ViewBag.RedirectUri = RedirectUri;
            return View();
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                //await HttpContext.SignOutAsync();
                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            if (!string.IsNullOrEmpty(vm.PostLogoutRedirectUri))
                return Redirect(vm.PostLogoutRedirectUri);

            return RedirectToAction("Index", "Home", vm.PostLogoutRedirectUri);
        }



        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null)
            {
                // this is meant to short circuit the UI and only trigger the one external IdP
                return new LoginViewModel
                {
                    EnableLocalLogin = false,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                    ExternalProviders = new ExternalProvider[] { new ExternalProvider { AuthenticationScheme = context.IdP } },
                };
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            string domain;
            if (string.IsNullOrEmpty(context?.RedirectUri))
            {
                domain = HttpContext.Request.Host.Host;            
            }
            else
            {
                domain = new Uri(context?.RedirectUri)?.GetLeftPart(UriPartial.Authority);
            }
            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray(),
                ForgotPasswordLoginUri = domain+"/Login.aspx"
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }

       [HttpGet]
       public IActionResult ForgotPassword(LoginInputModel model)
       {
            ForgotPasswordViewModel forgotPasswordViewModel = new ForgotPasswordViewModel()
            {
                ForgotPasswordLoginUri = model.ForgotPasswordLoginUri
            };
            return View(forgotPasswordViewModel);
       }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if(string.IsNullOrEmpty(model.EmailAddress))
            {
                ModelState.AddModelError("EmailAddress", "EmailAddress required");
                return View(model);
            }

            var users = _user.GetAllUserByUsernameAndEmail(model.EmailAddress);
            var toSendEmail = _user.GetUserByUsernameOrEmail(model.EmailAddress);

            if (!users.Any())
            {
                ModelState.AddModelError("EmailAddress", "Invalid Email/Username Address");
                return View(model);
            }

            var vmodel = await _user.ProcessForgotPassword(model, users);

            var messageBody = await _emailRenderer.RenderViewToStringAsync("/Views/Emails/PasswordReset.cshtml", vmodel);
            await _emailSender.SendEmailAsync(toSendEmail.Email, "Confirm your account",messageBody);

            model.isEmailConfirmed = toSendEmail.EmailConfirmed;
            return View(model);
        }


    }

    public class AuthenticateResultModel
    {
        public string AccessToken { get; set; }

        public string EncryptedAccessToken { get; set; }

        public int ExpireInSeconds { get; set; }

        public bool ShouldResetPassword { get; set; }

        public string PasswordResetCode { get; set; }

        public string UserId { get; set; }

        public bool RequiresTwoFactorVerification { get; set; }

        public IList<string> TwoFactorAuthProviders { get; set; }

        public string TwoFactorRememberClientToken { get; set; }

        public string ReturnUrl { get; set; }

        public string RefreshToken { get; set; }
    }

    public class AuthenticateModel
    {
        [Required]
        public string UserNameOrEmailAddress { get; set; }

        [Required]
        public string Password { get; set; }

        public string TwoFactorVerificationCode { get; set; }

        public bool RememberClient { get; set; }

        public string TwoFactorRememberClientToken { get; set; }

        public bool? SingleSignIn { get; set; }

        public string ReturnUrl { get; set; }

        public string CaptchaResponse { get; set; }
    }

    public class LoginException 
    {
        public LoginException(string message, string error)
        {
            Message = message;
            Error = error;
        }

        public string Message { get; set; }
        public string Error { get; set; }
    }
}