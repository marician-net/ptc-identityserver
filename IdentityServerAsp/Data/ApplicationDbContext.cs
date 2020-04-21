using System;
using System.Collections.Generic;
using System.Text;
using IdentityServerAsp.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityServerAsp.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUsers>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {

        }

        public DbSet<ApplicationUsers> ApplicationUsers { get; set; }
        public DbSet<IdentityRole> IdentityRole { get; set; }
    }
}
