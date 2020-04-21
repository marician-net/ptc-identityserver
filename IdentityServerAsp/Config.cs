    using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Models;
using System.Security.Claims;
    using System.Text;
    using IdentityServer4;
using IdentityServerAsp.Models;
    using Microsoft.IdentityModel.Tokens;

    namespace IdentityServerAsp
{
    public class Config
    {
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

        public static IEnumerable<ApplicationUsers> GetApplicationUsers()
        {
            return new List<ApplicationUsers>
            {
                //Group of usernames under one email
                new ApplicationUsers
                {
                    firstName="Jeff",
                    lastName="Newboles",
                    UserName="jeff@nationalcompliance.com",
                    PasswordHash="AQAAAAEAACcQAAAAEAb2k3jwmbcHL1+qenWLoIrrn9I6blTv+fJzBjSKCDAmpZB6woLX53O6CHEgw36iQg==",
                    SecurityStamp="HVVBVGCCPVNZ6ZXMLWJTN3WSYC46CDCP",
                    Email="jeff@nationalcompliance.com",
                    NormalizedEmail = "jeff@nationalcompliance.com".ToUpperInvariant(),
                    IsAdmin=true,
                    ptcOnlineId = "ptctp"
                },
                new ApplicationUsers
                {
                    firstName="Jeff",
                    lastName="Newboles",
                    UserName="jeff+1@nationalcompliance.com",
                    PasswordHash="AQAAAAEAACcQAAAAEAb2k3jwmbcHL1+qenWLoIrrn9I6blTv+fJzBjSKCDAmpZB6woLX53O6CHEgw36iQg==",
                    SecurityStamp="HVVBVGCCPVNZ6ZXMLWJTN3WSYC46CDCP",
                    Email="jeff@nationalcompliance.com",
                    NormalizedEmail = "jeff@nationalcompliance.com".ToUpperInvariant(),
                    IsAdmin=true,
                    ptcOnlineId = "ptctp"
                },
                new ApplicationUsers
                {
                    firstName="Jeff",
                    lastName="Newboles",
                    UserName="jeff+2@nationalcompliance.com",
                    PasswordHash="AQAAAAEAACcQAAAAEAb2k3jwmbcHL1+qenWLoIrrn9I6blTv+fJzBjSKCDAmpZB6woLX53O6CHEgw36iQg==",
                    SecurityStamp="HVVBVGCCPVNZ6ZXMLWJTN3WSYC46CDCP",
                    Email="jeff@nationalcompliance.com",
                    NormalizedEmail = "jeff@nationalcompliance.com".ToUpperInvariant(),
                    IsAdmin=true,
                    ptcOnlineId = "ptctp"
                },

                new ApplicationUsers
                {
                    firstName="Jeff",
                    lastName="Martens",
                    UserName="jeff@pipelinetesting.com",
                    PasswordHash="AQAAAAEAACcQAAAAEAb2k3jwmbcHL1+qenWLoIrrn9I6blTv+fJzBjSKCDAmpZB6woLX53O6CHEgw36iQg==",
                    SecurityStamp="HVVBVGCCPVNZ6ZXMLWJTN3WSYC46CDCP",
                    Email="jeff@pipelinetesting.com",
                    NormalizedEmail = "jeff@pipelinetesting.com".ToUpperInvariant(),
                    IsAdmin=true,
                    ptcOnlineId = "ptctp"
                },
                new ApplicationUsers
                {
                    firstName="Justin",
                    lastName="Unruh",
                    UserName="justin@pipelinetesting.com",
                    PasswordHash="AQAAAAEAACcQAAAAEAb2k3jwmbcHL1+qenWLoIrrn9I6blTv+fJzBjSKCDAmpZB6woLX53O6CHEgw36iQg==",
                    SecurityStamp="HVVBVGCCPVNZ6ZXMLWJTN3WSYC46CDCP",
                    Email="justin@pipelinetesting.com",
                    NormalizedEmail = "justin@pipelinetesting.com".ToUpperInvariant(),
                    IsAdmin=true,
                    ptcOnlineId = "ptctp"
                }
            };
        }

        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = "ptcClientDev",
                    ClientName = "PTCOnline Client",
                    AllowedGrantTypes = GrantTypes.HybridAndClientCredentials,

                    RequireConsent = false,

                    ClientSecrets =
                    {
                        new Secret("ptc$123Secur1ty".Sha256())
                    },

                    RedirectUris = {"http://localhost:5011/signin-oidc"},
                    PostLogoutRedirectUris = {"http://localhost:5011/"},
                    FrontChannelLogoutUri = "http://localhost:5011/logout.aspx",


                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "name",
                        "userapi",
                        "roles",
                        "UserName"
                    },
                    AllowOfflineAccess = true,
                    AlwaysIncludeUserClaimsInIdToken = true
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

                    RedirectUris = {"http://localhost:5010/signin-oidc"},
                    PostLogoutRedirectUris = {"http://localhost:5010/"},
                    BackChannelLogoutUri = "http://localhost:5010/signout-oidc",


                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
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

                    RedirectUris = {"http://localhost:5011/signin-oidc"},
                    PostLogoutRedirectUris = {"http://localhost:5011/"},
                    BackChannelLogoutUri = "http://localhost:5011/signout-oidc",



                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "name",
                        "userapi",
                        "roles",
                        "UserName"
                    },
                    AllowOfflineAccess = true,
                    AlwaysIncludeUserClaimsInIdToken = true
                },
                new Client
                {
                    ClientId = "mvcboiler",
                    ClientName = "MVCBOILER Client",
                    AllowedGrantTypes = GrantTypes.Hybrid,

                    RequireConsent = true,

                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    RedirectUris = {"http://localhost:62114/signin-oidc"},
                    PostLogoutRedirectUris = {"http://localhost:62114/"},
                    BackChannelLogoutUri = "http://localhost:62114/signout-oidc",


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
                    ClientId = "angular_spa",
                    ClientName = "Angular SPA",
                    AllowedGrantTypes = GrantTypes.ImplicitAndClientCredentials,

                    RequireConsent = false,

                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "userapi"
                    },
                    RedirectUris = {"http://localhost:4200/auth-callback"},
                    PostLogoutRedirectUris = {"http://localhost:4200/"},
                    AllowedCorsOrigins = {"http://localhost:4200"},
                    AllowOfflineAccess = true,
                    AllowAccessTokensViaBrowser = true,
                    AccessTokenLifetime = 3600,
                    AccessTokenType = AccessTokenType.Jwt,
                }
            };

        }
    }
}
