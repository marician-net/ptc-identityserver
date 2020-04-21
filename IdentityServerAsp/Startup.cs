using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using IdentityServerAsp.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using IdentityServer4.EntityFramework.DbContexts;
using System.Reflection;
using IdentityServer4.EntityFramework.Mappers;
using IdentityServerAsp.Models;
using IdentityServerAsp.Abstractions;
using IdentityServerAsp.Services;
using System.Security.Claims;
using IdentityModel;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;
using IdentityServerAsp.Helpers;
using Microsoft.AspNetCore.Razor.Language;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Tokens;
using Serilog;

/// <summary>
/// PTC Code base
/// </summary>
namespace IdentityServerAsp
{
    public class Startup
    {
        public static SigningCredentials SigningCredentials = null;
        public static string Authority = null;

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            string dbconnectionstring = "";
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PTCIdentityServer", EnvironmentVariableTarget.Machine)))
            {
                dbconnectionstring = Environment.GetEnvironmentVariable("PTCIdentityServer", EnvironmentVariableTarget.Machine);
            }
            else
            {
                dbconnectionstring = Configuration.GetConnectionString("DefaultConnection");
            }
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            //Set the Authority
            Authority = Configuration["IdentityServer:Authority"].ToString();

            services.AddScoped<IUserService,UserService>();
            services.AddScoped<UserManager<ApplicationUsers>>();
            services.AddScoped<RoleManager<IdentityRole>>();
            services.AddScoped<IIdentityEmailSender, IdentityServerEmail>();
            services.AddTransient<IRazorViewToEmailRenderer, RazorViewToEmailRenderer>();
           
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(dbconnectionstring));

            var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";
            services.AddCors(options =>
            {
                options.AddPolicy(MyAllowSpecificOrigins,
                    builder =>
                    {
                        builder.AllowAnyOrigin()
                            .AllowAnyHeader()
                            .AllowAnyMethod();
                    });
            });

            services.AddIdentity<ApplicationUsers, IdentityRole>()
                .AddDefaultTokenProviders()
                //.AddDefaultUI()
                .AddEntityFrameworkStores<ApplicationDbContext>();


            // configure identity server with in-memory stores, keys, clients and scopes
            services.AddIdentityServer(options =>
                {
                    options.UserInteraction.LoginUrl = "/account/login";
                    options.UserInteraction.LogoutUrl = "/account/logout";
                })
                .AddJwtBearerClientAuthentication()
                //
                //TODO:  Comment out this line .AddDeveloperSigningCredential()
                //
                //.AddDeveloperSigningCredential()
                //
                //TODO:  You will need to configure a SigningCredential Here
                .AddSigningCredential(GetIdentityServerCertificate())
                //
                // this adds the config data from DB (clients, resources)
                .AddConfigurationStore(options =>
                {                    
                    options.ConfigureDbContext = builder =>
                        builder.UseSqlServer(dbconnectionstring,
                            sql => sql.MigrationsAssembly(migrationsAssembly));
                })
                // this adds the operational data from DB (codes, tokens, consents)
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = builder =>
                        builder.UseSqlServer(dbconnectionstring,
                            sql => sql.MigrationsAssembly(migrationsAssembly));

                    // this enables automatic token cleanup. this is optional.
                    options.EnableTokenCleanup = true;
                    options.TokenCleanupInterval = 30;
                })
                .AddAspNetIdentity<ApplicationUsers>()
                .AddProfileService<CustomClaimsService>();

            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = "Cookie";
                    options.DefaultChallengeScheme = "Cookie";
                })
                .AddJwtBearer(options =>
                {
                    options.Authority = Configuration.GetSection("IdentityServer")["Authority"];
                    options.Audience = "userapi";
                    options.RequireHttpsMetadata = Configuration.GetSection("IdentityServer")["RequireHttpsMetadata"] != "N";
                })
                .AddCookie("Cookie", options =>
                {
                    options.ExpireTimeSpan = new TimeSpan(1, 0, 0);
                    options.SlidingExpiration = true;
                });


            services.AddAuthorization(options => { options.AddPolicy("Admin", policy=> policy.RequireRole("Admin")); });

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddFile("Logs/myapp-{Date}.txt");

            IServiceScopeFactory scopeFactory = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>();
            DbInitalizer.InitializeDatabase(app).Wait();
            
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseCors("_myAllowSpecificOrigins");

            app.UseIdentityServer();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private X509Certificate2 GetIdentityServerCertificate()
        {
            var clientId = Configuration.GetSection("CodeSigningCert")["ClientID"];
            var clientSecret = Configuration.GetSection("CodeSigningCert")["ClientSecret"];
            var secretIdentifier = Configuration.GetSection("CodeSigningCert")["SecretIdentifier"];

            var keyVaultClient = new KeyVaultClient(async (authority, resource, scope) =>
            {
                var authContext = new AuthenticationContext(authority);
                ClientCredential clientCreds = new ClientCredential(clientId, clientSecret);

                AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCreds);

                if (result == null)
                {
                    throw new InvalidOperationException("Failed to obtain the JWT token");
                }

                return result.AccessToken;
            });

            Log.Logger.Information($"Secret: {secretIdentifier}");
            var pfxSecret = keyVaultClient.GetSecretAsync(secretIdentifier).Result;
            var pfxBytes = Convert.FromBase64String(pfxSecret.Value);
            var certificate = new X509Certificate2(pfxBytes, "",
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet |
                X509KeyStorageFlags.Exportable);

            SigningCredentials = new X509SigningCredentials(certificate);

            return certificate;
        }

    }

    public static class DbInitalizer
    {
        public static async Task InitializeDatabase(IApplicationBuilder app)
        {
            using (var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            {
                serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

                var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
                var userContext= serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                context.Database.Migrate();
                userContext.Database.Migrate();

                foreach (var client in Config.GetClients())
                {
                    if (!context.Clients.Any(x => x.ClientId == client.ClientId))
                    {
                        context.Clients.Add(client.ToEntity());
                    }
                }
                context.SaveChanges();

                if (!context.IdentityResources.Any())
                {
                    foreach (var resource in Config.GetIdentityResources())
                    {
                        context.IdentityResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.ApiResources.Any())
                {
                    foreach (var resource in Config.GetApiResources())
                    {
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!userContext.ApplicationUsers.Any())
                {
                    foreach (var users in Config.GetApplicationUsers())
                    {
                        userContext.ApplicationUsers.Add(users);
                    }
                    userContext.SaveChanges();
                }

                var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                if (!await roleManager.RoleExistsAsync("Admin"))
                {

                    using (var contextApp = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>())
                    {
                        var userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<ApplicationUsers>>();

                        var role = new IdentityRole("Admin");
                        var res = await roleManager.CreateAsync(role);
                        var jn = contextApp.ApplicationUsers.FirstOrDefault(x => x.Email == "jeff@nationalcompliance.com");
                        var jm = contextApp.ApplicationUsers.FirstOrDefault(x => x.Email == "jeff@pipelinetesting.com");
                        var ju = contextApp.ApplicationUsers.FirstOrDefault(x => x.Email == "justin@pipelinetesting.com");
                        await userManager.AddToRoleAsync(jn, "Admin");
                        await userManager.AddToRoleAsync(jm, "Admin");
                        await userManager.AddToRoleAsync(ju, "Admin");

                        //await userManager.AddToRoleAsync(user, "Admin");
                        //var user = contextApp.ApplicationUsers.FirstOrDefault(x => x.Email == "Admin@ptc.com");
                        //var claims = new List<Claim>
                        //{
                        //    new Claim(JwtClaimTypes.Name,user.firstName),
                        //    new Claim(JwtClaimTypes.FamilyName,"Admin"),
                        //    new Claim("UserName",user.UserName),
                        //    new Claim("roles","Client"),
                        //    new Claim(JwtClaimTypes.Role,"Client"),
                        //};

                        //await userManager.AddToRoleAsync(user, "Admin");
                        //await userManager.AddClaimsAsync(user, claims);

                        contextApp.SaveChanges();
                    }
                }

            }

        }
    }
}
