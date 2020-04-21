using IdentityServerAsp.Models;
using IdentityServerAsp.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerAsp.Abstractions
{
    public interface IUserService
    {
        IEnumerable<ApplicationUsers> GetAllUsers();

        ApplicationUsers GetUserById(string userId);

        ApplicationUsers GetUserByName(string username);

        List<ApplicationUsers> GetAllUserByUsernameAndEmail(string filterString);

        ApplicationUsers GetUserByUsernameOrEmail(string emailOrUsername);

        Task AddorUpdate(ApplicationUsers applicationUsers, string confirmedLoginUri);

        Task<UserViewModel> AddorUpdate(UserViewModel userViewModel, string confirmedLoginUri);

        Task SuspendUsers(ApplicationUsers applicationUsers);

        Task DeleteUsers(ApplicationUsers applicationUsers);

        Task ResumeUsers(ApplicationUsers applicationUsers);

        UserModel GetUsers(int currentPage);

        Task SendEmail(ApplicationUsers user, string confirmedLoginUri);

        string GetHtmlTemplate(string templateName);

        Task<List<ForgotPasswordUserNameViewModel>> ProcessForgotPassword(ForgotPasswordViewModel model,
            List<ApplicationUsers> users);
    }
}
