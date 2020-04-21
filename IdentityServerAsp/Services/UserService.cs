using IdentityServerAsp.Abstractions;
using IdentityServerAsp.Data;
using IdentityServerAsp.Models;
using IdentityServerAsp.ViewModel;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Linq;
using System.Security.Policy;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Identity.UI.Services;
using MimeKit;
using System.IO;
using Microsoft.AspNetCore.Hosting;
using System.Diagnostics;

namespace IdentityServerAsp.Services
{
    public class UserService : IUserService
    {
        public const string email_Password = "PasswordReset.html";
        private const string email_SupervisorPassword = "SupervisorTrainingWelcome.html";
        private readonly ApplicationDbContext _applicationDBContext;
        private readonly UserManager<ApplicationUsers> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private IIdentityEmailSender _emailSender;
        private IHostingEnvironment _env;

        public UserService(ApplicationDbContext applicationDbContext, IHostingEnvironment env, UserManager<ApplicationUsers> userManager, RoleManager<IdentityRole> roleManager, IIdentityEmailSender emailSender)
        {
            _applicationDBContext = applicationDbContext;
            _userManager = userManager;
            _roleManager = roleManager;
            _env = env;
            _emailSender = emailSender;
        }
        public IEnumerable<ApplicationUsers> GetAllUsers()
        {
            return _applicationDBContext.ApplicationUsers;
        }

        public ApplicationUsers GetUserById(string userId)
        {
            return _applicationDBContext.ApplicationUsers.FirstOrDefault(m => m.Id == userId);
        }

        public ApplicationUsers GetUserByName(string username)
        {
            return _applicationDBContext.ApplicationUsers.FirstOrDefault(m => String.Equals(m.UserName, username.Trim(), StringComparison.CurrentCultureIgnoreCase));
        }

        public List<ApplicationUsers> GetUsersByEmail(string email)
        {
            return _applicationDBContext.ApplicationUsers.Where(m => String.Equals(m.Email, email.Trim(), StringComparison.CurrentCultureIgnoreCase)).ToList();
        }

        public List<ApplicationUsers> GetAllUserByUsernameAndEmail(string filterString)
        {
            var users = new List<ApplicationUsers>();
            var user = GetUserByName(filterString);
            if(user!=null) users.Add(user);
            var usersByEmail = GetUsersByEmail(filterString);
            users.AddRange(usersByEmail);
            return users.Distinct().ToList();
        }

        public ApplicationUsers GetUserByUsernameOrEmail(string emailOrUsername)
        {
            var user = GetUserByName(emailOrUsername);
            return user ?? GetUsersByEmail(emailOrUsername).FirstOrDefault();
        }

        public async Task<List<ForgotPasswordUserNameViewModel>> ProcessForgotPassword(ForgotPasswordViewModel model, List<ApplicationUsers> users)
        {
            var vmodel = new List<ForgotPasswordUserNameViewModel>();
            foreach (var user in users)
            {
                var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var encodedToken = Uri.EscapeDataString(emailToken);

                var callbackUrl = await _emailSender.CreateCallbackUrl("ConfirmEmail", "Account", model.ForgotPasswordLoginUri,
                    new { userId = user.Id, code = encodedToken });
                vmodel.Add(new ForgotPasswordUserNameViewModel()
                {
                    CallbackUrl = callbackUrl,
                    Firstname = user.firstName,
                    Lastname = user.lastName,
                    Username = user.UserName,
                    Email = user.Email
                });
            }

            return vmodel;
        }


        public async Task AddorUpdate(ApplicationUsers applicationUsers, string confirmedLoginUri)
        {

            var entity = GetUserById(applicationUsers.Id);
            if (applicationUsers.Id == null)
            {
                _applicationDBContext.ApplicationUsers.Add(applicationUsers);
                _applicationDBContext.SaveChanges();
                await SendEmail(applicationUsers, confirmedLoginUri);

            }
            else
            {

                entity.firstName = applicationUsers.firstName;
                entity.lastName = applicationUsers.lastName;
                entity.UserName = applicationUsers.UserName;
                entity.Email = applicationUsers.Email;
                entity.IsAdmin = applicationUsers.IsAdmin;
                entity.ptcOnlineId = applicationUsers.ptcOnlineId;
                if(entity.SecurityStamp==null)
                {
                    entity.SecurityStamp = Guid.NewGuid().ToString();
                }
               
                _applicationDBContext.ApplicationUsers.Update(entity);
            }

            await _applicationDBContext.SaveChangesAsync();

            if (applicationUsers.IsAdmin)
            {
                var result = await _userManager.AddToRoleAsync(entity, "Admin");
            }

            await _applicationDBContext.SaveChangesAsync();
        }

        public async Task SendEmail(ApplicationUsers applicationUsers, string confirmedLoginUri)
        {
            var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(applicationUsers);
            var encodedToken = Uri.EscapeDataString(emailToken);
            var callbackUrl = await _emailSender.CreateCallbackUrl("ConfirmEmail", "Account", confirmedLoginUri,
                              new { userId = applicationUsers.Id, code = encodedToken });

           string messageBody = string.Format(GetHtmlTemplate(email_Password), applicationUsers.firstName,applicationUsers.UserName, HtmlEncoder.Default.Encode(callbackUrl));
            try
            {
                await _emailSender.SendEmailAsync(applicationUsers.Email, "Confirm your account",
                messageBody);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public async Task SendSuperVisorEmail(ApplicationUsers applicationUsers, string companyName, string password)
        {
            string messageBody = string.Format(GetHtmlTemplate(email_SupervisorPassword), companyName, applicationUsers.UserName, password);
            await _emailSender.SendEmailAsync(applicationUsers.Email, "Supervisor Training Login",
                 messageBody);
        }

        public string GetHtmlTemplate(string templateName)
        {
            var builder = new BodyBuilder();
            var webRoot = _env.WebRootPath;
            var pathToFile = _env.WebRootPath
                            + Path.DirectorySeparatorChar.ToString()
                            + "Template"
                            + Path.DirectorySeparatorChar.ToString()
                            + "EmailTemplate"
                            + Path.DirectorySeparatorChar.ToString()
                            + templateName;
            using (StreamReader SourceReader = System.IO.File.OpenText(pathToFile))
            {

                builder.HtmlBody = SourceReader.ReadToEnd();

            }
            return builder.HtmlBody;
        }

        public async Task<UserViewModel> AddorUpdate(UserViewModel userViewModel, string confirmedLoginUri)
        {

            var users = userViewModel.Id!=null
                ? GetUserById(userViewModel.Id)
                : new ApplicationUsers();

            users.firstName = userViewModel.firstName;
            users.lastName= userViewModel.lastName;
            users.UserName = userViewModel.UserName ;
            users.Email = userViewModel.Email;
            users.IsAdmin= userViewModel.IsAdmin;
            users.ptcOnlineId = userViewModel.UserName;
           
            if (userViewModel.Id == null)
            {
                if (userViewModel.IsSupervisor)
                {
                    var result = await _userManager.CreateAsync(users, userViewModel.Password ?? "pass$$Word@1");

                    users.EmailConfirmed = true;
                    _applicationDBContext.SaveChanges();

                    Debug.WriteLine($"User={users.UserName} Password={userViewModel.Password}");
                    if (result.Succeeded)
                    {
                        _applicationDBContext.SaveChanges();
                        await SendSuperVisorEmail(users, userViewModel.CompanyName, userViewModel.Password);
                    }
                }
                else
                {
                    var result = await _userManager.CreateAsync(users);
                    if (result.Succeeded)
                    {
                        _applicationDBContext.SaveChanges();
                        try
                        {
                            await SendEmail(users, confirmedLoginUri);
                        } catch (Exception ex)
                        {
                            Console.WriteLine(ex.Message);
                        }
                    }
                }
            }
            else
            {

                _applicationDBContext.ApplicationUsers.Update(users);

            }

            await _applicationDBContext.SaveChangesAsync();

            if (users.IsAdmin)
            {
              
                var result = await _userManager.AddToRoleAsync(users, "Admin");

            }

            await _applicationDBContext.SaveChangesAsync();

            return userViewModel;
        }

        public async Task DeleteUsers(ApplicationUsers user)
        {
            if(user==null) return;
            try{
                await _userManager.DeleteAsync(user);
            }
            catch
            {
                return;
            }
        }


        public async Task SuspendUsers(ApplicationUsers applicationUsers)
        {
            applicationUsers.LockoutEnabled = true;
            applicationUsers.LockoutEnd = DateTimeOffset.MaxValue;
            await _applicationDBContext.SaveChangesAsync();
        }

        public async Task ResumeUsers(ApplicationUsers applicationUsers)
        {
            applicationUsers.LockoutEnabled = false;
            applicationUsers.LockoutEnd = null;
            await _applicationDBContext.SaveChangesAsync();
        }

        public UserModel GetUsers(int currentPage)
        {
            int maxRows = 5;
           
                UserModel userModel = new UserModel();

                userModel.ApplicationUsers = (from user in _applicationDBContext.ApplicationUsers
                                           select user)
                            .OrderBy(user => user.Id)
                            .Skip((currentPage - 1) * maxRows)
                            .Take(maxRows).ToList();

                double pageCount = (double)((decimal)_applicationDBContext.ApplicationUsers.Count() / Convert.ToDecimal(maxRows));
                userModel.PageCount = (int)Math.Ceiling(pageCount);

                userModel.CurrentPageIndex = currentPage;

                return userModel;
            
        }
    }

}
