using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using TodoListWebApp.Utils;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Data.SqlClient;
using System.Web.Configuration;

namespace TodoListWebApp.Controllers
{
    public class HomeController : Controller
    {
        private string todoListBaseAddress = ConfigurationManager.AppSettings["todo:TodoListBaseAddress"];
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string svcId = ConfigurationManager.AppSettings["ida:ClientIdSqlAadApp"];
        private static string svcPwd = ConfigurationManager.AppSettings["ida:ClientSecretSqlAadApp"];
        private static string appKey = ConfigurationManager.AppSettings["ida:AppKey"];
        private string todoListResourceId = ConfigurationManager.AppSettings["todo:TodoListResourceId"];
        private const string ResourceId = "https://database.windows.net/";
        private static string sqlDBResourceId = ConfigurationManager.AppSettings["sqldb:ResourceId"];
        
        public ActionResult Index()
        {
            

            
            return View();
        }

        public ActionResult About()
        {
            //AuthenticationContext authenticationContext = new AuthenticationContext(Startup.Authority);
            //var userCredential = new UserPasswordCredential("svcAccntName@fqdn-tenant.com", "pwd");
            //AuthenticationResult authenticationResult = authenticationContext.AcquireTokenAsync(ResourceId, "460ec31c-3178-4308-a371-1c5046312151", userCredential).Result;
            //ViewBag.Token = authenticationResult.AccessToken;

            

            //var clientID = WebConfigurationManager.AppSettings["ClientId"];         //coming from app settings
            //var clientSecret = WebConfigurationManager.AppSettings["ClientSecret"]; //coming from app settings
            var t = Task.Run(async () => await TokenFactory.GetToken(Startup.Authority, sqlDBResourceId, "", svcId, svcPwd));
            string accessToken = t.Result;
            string msg = string.Empty;
            if (accessToken == null)
            {
                msg = ("Fail to acuire the token to the database.");
                ViewBag.IsConnectedToAzureSql = "No Token hence not validating sql connection.";
            }
            else
            {
                msg = accessToken;
                ViewBag.IsConnectedToAzureSql = ValidateAzureSqlAuthentication(accessToken);
            }

            ViewBag.Message = "Your application description page." ;
            ViewBag.Name = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value;
            ViewBag.ObjectId = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
            ViewBag.GivenName = ClaimsPrincipal.Current.FindFirst(ClaimTypes.GivenName).Value;
            ViewBag.Surname = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Surname).Value;
            ViewBag.UPN = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn).Value;

            //ClaimsIdentity claimsId = ClaimsPrincipal.Current.Identity as ClaimsIdentity;
            //var appRoles = new List<String>();
            //foreach (Claim claim in claimsId.Claims)
            //{
            //    appRoles.Add(String.Format("Type={0}, Value={1}, ValueType={2}, Subject={3}, Issuer={4}",
            //        claim.Type, claim.Value, claim.ValueType, claim.Subject, claim.Issuer));
            //}

            ViewBag.Roles = ClaimsPrincipal.Current.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();

            return View();
        }

        public async Task<ActionResult> Contact()
        {
            // Get user access token
            AuthenticationResult result = null;
            try
            {
                string userObjectID = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
                AuthenticationContext authContext = new AuthenticationContext(Startup.Authority, new RedisTokenCache(userObjectID));
                ClientCredential credential = new ClientCredential(clientId, appKey);
                result = await authContext.AcquireTokenSilentAsync(todoListResourceId, credential, new UserIdentifier(userObjectID, UserIdentifierType.UniqueId));
                //

                // Send barer token to webapi request.
                string resultValue = string.Empty;
                HttpClient client = new HttpClient();
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, todoListBaseAddress + "/api/values");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
                HttpResponseMessage response = await client.SendAsync(request);
                if (response.IsSuccessStatusCode)
                {
                    String responseString = await response.Content.ReadAsStringAsync();
                    ViewData["appRoles"] = responseString;
                }
                else
                {
                    //
                    // If the call failed with access denied, then drop the current access token from the cache, 
                    //     and show the user an error indicating they might need to sign-in again.
                    //
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        var todoTokens = authContext.TokenCache.ReadItems().Where(a => a.Resource == todoListResourceId);
                        foreach (Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCacheItem tci in todoTokens)
                            authContext.TokenCache.DeleteItem(tci);

                        ViewBag.ErrorMessage = "UnexpectedError";
                        return View();
                    }
                }
                //
                ViewBag.Message = "Your contact page.";
            }
            catch (AdalException ee)
            {
                if (Request.QueryString["reauth"] == "True")
                {
                    //
                    // Send an OpenID Connect sign-in request to get a new set of tokens.
                    // If the user still has a valid session with Azure AD, they will not be prompted for their credentials.
                    // The OpenID Connect middleware will return to this controller after the sign-in response has been handled.
                    //



                    HttpContext.GetOwinContext().Authentication.Challenge(
                        new AuthenticationProperties(),
                        OpenIdConnectAuthenticationDefaults.AuthenticationType);

                }

                ViewBag.ErrorMessage = "AuthorizationRequired";
            }
            return View();
        }

        public ActionResult Error(string message)
        {
            ViewBag.Message = message;
            return View("Error");
        }

        private bool ValidateAzureSqlAuthentication(string accessToken)
        {
            bool isConnected = false;
            SqlConnectionStringBuilder builder = new SqlConnectionStringBuilder();
            builder["Data Source"] = "cla-zue1-sql-01-d.database.windows.net"; // replace with your server name
            builder["Initial Catalog"] = "cla"; // replace with your database name
            builder["Connect Timeout"] = 30;
            using (SqlConnection connection = new SqlConnection(builder.ConnectionString))
            {
                try
                {
                    connection.AccessToken = accessToken;
                    connection.Open();
                    ViewBag.Message += ("Connected to the database");
                    isConnected = true;
                }
                catch (Exception ex)
                {
                    ViewBag.Message += (ex.Message);
                }
            }
            
            return isConnected;
        }
    }
}