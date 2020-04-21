using IdentityServerAsp.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerAsp
{
    public class UserViewModel
    {


        public string Id { get; set; }
        public string firstName { get; set; }
        public string lastName { get; set; }
        public string Email { get; set; }

        public bool IsAdmin { get; set; }
        public string UserName { get; set; }
        public string ptcOnlineId { get; set; }
        public bool IsSupervisor { get; set; }
        public string CompanyName { get; set; }
        public string Password { get; set; }
    }


    public class UserModel
    {
        public int CurrentPageIndex { get; set; }
        public int PageCount { get; set; }

        public List<ApplicationUsers> ApplicationUsers { get; set; }


    }
}
