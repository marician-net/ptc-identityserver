using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Threading.Tasks;
using IdentityServerAsp.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Extensions.Configuration;

namespace IdentityServerAsp.Services
{
    public class IdentityServerEmail: IIdentityEmailSender 
    {
        private readonly IConfiguration _config;

        public IdentityServerEmail(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var smtp = new SmtpClient()
            {
                DeliveryMethod = SmtpDeliveryMethod.SpecifiedPickupDirectory,
                PickupDirectoryLocation = _config.GetSection("IdentityServer")["EmailDirectory"]                
            };
            var message = new MailMessage()
            {
                Subject = subject,
                IsBodyHtml = true,
                Body = htmlMessage,
                To = { new MailAddress(email)},
                From = new MailAddress(_config.GetSection("IdentityServer")["EmailFromAddress"])
            };
            await smtp.SendMailAsync(message);
        }

        public async Task<string> CreateCallbackUrl(string Action, string Controller, string redirectUri, dynamic model)
        {
            var uri = _config.GetSection("IdentityServer")["Authority"] + "/" + Controller + "/" + Action +
                         "?username=" + model.userId + 
                         "&redirectUri="+ redirectUri + 
                         "&code=" + model.code;
            return await Task.FromResult(uri);
        }

    }
}
