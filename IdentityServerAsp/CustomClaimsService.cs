using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServerAsp.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityServerAsp
{
    public class CustomClaimsService: IProfileService
    {
        private readonly UserManager<ApplicationUsers> _userManager;

        public CustomClaimsService(UserManager<ApplicationUsers> userManager)
        {
            _userManager = userManager;
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var sub = context.Subject.GetSubjectId();
            if (sub == null) return;
            var user = await _userManager.FindByIdAsync(sub);
            if (user == null) return;
            context.IssuedClaims.Add(new Claim("ptconlineId", user.ptcOnlineId ?? ""));
            context.IssuedClaims.Add(new Claim(ClaimTypes.Name, user.ptcOnlineId ?? ""));
        }

        public async Task IsActiveAsync(IsActiveContext context)
        {
            var sub = context.Subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(sub);
            context.IsActive = user != null;
        }
    }
}