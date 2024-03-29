﻿using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Test;

namespace IdentityServer
{
    public class Config
    {
        public static List<TestUser> GetUsers()
        {
            return new List<TestUser>
            {
                new TestUser
                {
                    SubjectId = "1",
                    Username = "alice",
                    Password = "password",

                    Claims = new []
                    {
                        new Claim("name", "Alice"),
                        new Claim("website", "https://alice.com")
                    }
                },
                new TestUser
                {
                    SubjectId = "2",
                    Username = "bob",
                    Password = "password",

                    Claims = new []
                    {
                        new Claim("name", "Bob"),
                        new Claim("website", "https://bob.com")
                    }
                }
            };
        }

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
            };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("userapi", "User API")
            };
         }   

        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = "mvc",
                    ClientName = "MVC Client",
                    AllowedGrantTypes = GrantTypes.Hybrid,

                    RequireConsent = true,

                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    RedirectUris           = { "http://localhost:5011/signin-oidc" },
                    PostLogoutRedirectUris = { "http://localhost:5011/" },
                    BackChannelLogoutUri   = "http://localhost:5011/signout-oidc" ,
                   

                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "name",
                        "userapi"
                    },
                    AllowOfflineAccess = true
                },
                new Client
                {
                    ClientId = "corewebapp",
                    ClientName = "WebApp Client",
                    AllowedGrantTypes = GrantTypes.Hybrid,

                    RequireConsent = true,

                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    RedirectUris           = { "http://localhost:5010/signin-oidc" },
                    PostLogoutRedirectUris = { "http://localhost:5010/" },
                    BackChannelLogoutUri  =     "http://localhost:5010/signout-oidc" ,
                    

                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "name",
                        "userapi"
                    },
                    AllowOfflineAccess = true
                },
                 new Client
                {
                    ClientId = "webforms",
                    ClientName = "WEBFORM Client",
                    AllowedGrantTypes = GrantTypes.Hybrid,

                    RequireConsent = true,

                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    RedirectUris = { "http://localhost:8080/authorization-code/callback" },
                    BackChannelLogoutUri  =     "http://localhost:8080/authorization-code/callback" ,
                    PostLogoutRedirectUris = { "http://localhost:8080/authorization-code/callback" },


                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "userapi"
                    },
                    AllowOfflineAccess = true
                }
            };

        }
     }
}
