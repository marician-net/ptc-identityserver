using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace IdentityServerAsp.Abstractions
{
    public interface IIdentityEmailSender: IEmailSender
    {
        Task<string> CreateCallbackUrl(string Action, string Controller, string redirectUri, dynamic model);
    }
}
