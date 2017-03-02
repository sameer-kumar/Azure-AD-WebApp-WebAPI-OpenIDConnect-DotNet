//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

// The following using statements were added for this sample.
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Configuration;
using System.Globalization;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Threading.Tasks;
using TodoListWebApp.Utils;
using System.Security.Claims;
using Microsoft.Owin.Security.Notifications;
using Microsoft.IdentityModel.Protocols;
using TodoListWebApp.App_Start;

namespace TodoListWebApp
{
    public partial class Startup
    {
        //
        // The Client ID is used by the application to uniquely identify itself to Azure AD.
        // The App Key is a credential used to authenticate the application to Azure AD.  Azure AD supports password and certificate credentials.
        // The Metadata Address is used by the application to retrieve the signing keys used by Azure AD.
        // The AAD Instance is the instance of Azure, for example public Azure or Azure China.
        // The Authority is the sign-in URL of the tenant.
        // The Post Logout Redirect Uri is the URL where the user will be redirected after they sign out.
        //
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string appKey = ConfigurationManager.AppSettings["ida:AppKey"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];

        public static readonly string Authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

        // This is the resource ID of the AAD Graph API.  We'll need this to request a token to call the Graph API.
        string graphResourceId = ConfigurationManager.AppSettings["ida:GraphResourceId"];

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions() { 
                //CookieSecure = CookieSecureOption.Always, //commented out for testing with http. un-comment it .
                // http://stackoverflow.com/questions/28559237/intermittent-redirection-loops-during-adfs-authentication
                CookieManager = new SystemWebCookieManager(),
                Provider = new CookieAuthenticationProvider
                {
                    OnResponseSignIn = context =>
                    {
                        context.Identity = TransformClaims(context, app);
                    }
                }
            });

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientId,
                    Authority = Authority,
                    PostLogoutRedirectUri = redirectUri,
                    RedirectUri = redirectUri,

                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        //
                        // If there is a code in the OpenID Connect response, redeem it for an access token and refresh token, and store those away.
                        //
                        AuthorizationCodeReceived = OnAuthorizationCodeReceived,
                        AuthenticationFailed = OnAuthenticationFailed
                    }

                });
        }

        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            context.HandleResponse();
            context.Response.Redirect("/Home/Error?message=" + context.Exception.Message);
            return Task.FromResult(0);
        }

        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification context)
        {
            var code = context.Code;

            ClientCredential credential = new ClientCredential(clientId, appKey);
            string userObjectID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
            AuthenticationContext authContext = new AuthenticationContext(Authority, new RedisTokenCache(userObjectID));

            // If you create the redirectUri this way, it will contain a trailing slash.  
            // Make sure you've registered the same exact Uri in the Azure Portal (including the slash).
            Uri uri = new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path));

            AuthenticationResult result = await authContext.AcquireTokenByAuthorizationCodeAsync(code, uri, credential, graphResourceId);
        }

        private static ClaimsIdentity TransformClaims(CookieResponseSignInContext ctx, IAppBuilder app)
        {
            var group_claimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups";
            var group_claimType_alternate = "groups";
            var identity = ctx.Identity;
            var groupsClaimExists = identity.Claims.Any(c => c.Type.Equals(group_claimType));
            var alternateGroupsClaimExists = identity.Claims.Any(c => c.Type.Equals(group_claimType_alternate));
            if (groupsClaimExists || alternateGroupsClaimExists)
            {
                //var userGroupClaims = from claims in identity.Claims
                //                      where claims.Type.Equals(group_claimType)
                //                      select claims;

                var userGroupClaims = from claims in identity.Claims
                                      where ((groupsClaimExists && claims.Type == group_claimType) || 
                                      (alternateGroupsClaimExists && claims.Type == group_claimType_alternate))
                                      select claims;

                var roleClaims = userGroupClaims
                    .Where(c => GetAadGroupNameById(c.Value) != null)
                    .Select(g => new Claim(ClaimTypes.Role, GetAadGroupNameById(g.Value), g.ValueType, g.Issuer));

                identity.AddClaims(roleClaims);
            }

            /*
            var claimEmail = ident.Claims.SingleOrDefault(c => c.Type == ClaimTypes.Email);
            var claimName = ident.Claims.SingleOrDefault(c => c.Type == ClaimTypes.Name);

            //normalize my string identifier
            var loginString = (claimEmail != null) ? claimEmail.Value : (claimName != null) ? claimName.Value : null;
            var efctx = ctx.OwinContext.Get<DBEntities>();

            var user = UserBL.GetActiveUserByEmailOrName(efctx, loginString);
            if (user == null)
            {
                //user was auth'd by ADFS but hasn't been auth'd by this app
                ident.AddClaim(new Claim(ClaimTypesCustom.Unauthorized, "true"));
                return ident;
            }

            if (ident.Claims.First().Issuer == "LOCAL AUTHORITY")
            {
                //Local
                //local already has claim type "Name"
                //local didn't have claim type "Email" - adding it
                ident.AddClaim(new Claim(ClaimTypes.Email, user.Email));
            }
            else
            {
                //ADFS
                //ADFS already has claim type "Email"
                //ADFS didn't have claim type "Name" - adding it
                ident.SetClaim(ClaimTypes.Name, user.UserName);
            }
            */
            //now ident has "Name" and "Email", regardless of where it came from
            return identity;
        }

        private static string GetAadGroupNameById(string groupId)
        {
            string groupName = null;
            var graphClient = new GraphClient("https://graph.windows.net/85c96496-fbc6-4bf3-bfcc-fb51ca874527");
            try
            {
                var groupNameTask = Task.Run(() => graphClient.GetGroupNameByIdAsync(groupId));//"29f4bef8-80bb-4afd-835f-16b3e0dbb537"
                groupName = groupNameTask.Result;
            }
            catch (Exception exception)
            {
                // look for specific exception in Graph Client library if groupId not found.
            }

            return groupName;
        }
    }
}