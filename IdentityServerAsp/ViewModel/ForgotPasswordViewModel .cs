using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerAsp.ViewModel
{
    public class ForgotPasswordViewModel
    {
        [Required(ErrorMessage = "The email address is required")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string EmailAddress { get; set; }

        public bool? isEmailConfirmed { get; set; }
        public string ForgotPasswordLoginUri { get; set; }
    }
}
