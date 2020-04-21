using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerAsp.ViewModel
{
    public class UserPasswordCheckViewModel
    {

        public string UserId { get; set; }


        [Required]
        [StringLength(100,ErrorMessage = "The {0} must be at least {2} and at max{1} characters long.",MinimumLength = 6)]
        public string Password { get; set; }

        [Compare("Password", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        public string RedirectUri { get; set; }

        public bool ResetAllUsernames { get; set; }
    }
}
