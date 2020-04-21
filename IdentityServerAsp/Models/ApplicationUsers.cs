using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServerAsp.Models
{
    public class ApplicationUsers: IdentityUser
    {
        public string firstName { get; set; }
        public string lastName { get; set; }
        public string ptcOnlineId { get; set; }

        public bool IsAdmin { get; set; }
        
    }

   
}
