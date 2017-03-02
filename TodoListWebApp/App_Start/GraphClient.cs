using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Azure.ActiveDirectory.GraphClient;

namespace TodoListWebApp.App_Start
{
    // https://gist.github.com/rytmis/4182440#file-graphclient-cs-L44
    // https://www.simple-talk.com/cloud/security-and-compliance/azure-active-directory-part-5-graph-api/
    public class GraphClient
    {
        //private readonly DirectoryDataService dataService;
        private readonly string tenantDomainName;
        private readonly string servicePrincipalSymmetricKey;
        private readonly string tenantId;
        private readonly string appPrincipalId;
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static readonly string authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string appKey = ConfigurationManager.AppSettings["ida:AppKey"];
        const string resAzureGraphAPI = "https://graph.windows.net";

        //public GraphClient(string tenantDomainName, string tenantId, string appPrincipalId, string servicePrincipalSymmetricKey)
        //{
        //    this.tenantDomainName = tenantDomainName;
        //    this.tenantId = tenantId;
        //    this.servicePrincipalSymmetricKey = servicePrincipalSymmetricKey;
        //    this.appPrincipalId = appPrincipalId;

        //    dataService = new DirectoryDataService(GetConnectionUri());
        //    dataService.SendingRequest += (sender, args) =>
        //    {
        //        var webRequest = ((HttpWebRequest)args.Request);
        //        webRequest.Headers.Add(HeaderName_Authorization, GetAuthorizationHeader());
        //        webRequest.Headers.Add(HeaderName_DataContractVersion, DataContractVersion);
        //        webRequest.Headers.Add(HeaderName_ClientRequestId, Guid.NewGuid().ToString());
        //    };
        //}

        /// <summary>
        /// Queries the Graph API for security groups in which an active user with the given
        /// <paramref name="userPrincipalName"/> is a direct member.
        /// </summary>
        //public IList<Group> GetUserGroups(string userPrincipalName)
        //{
        //    var user = dataService.Users
        //        .Where(u => u.AccountEnabled == true && u.UserPrincipalName == userPrincipalName)
        //        .AsEnumerable()
        //        .SingleOrDefault();

        //    var groupReferences = dataService.LoadProperty(user, "MemberOf")
        //        .OfType<ReferencedObject>()
        //        .Where(r => r.ObjectType == "Group")
        //        .Select(g => g.ObjectId);

        //    return dataService.Groups
        //        .AsEnumerable()
        //        .Where(g => groupReferences.Contains(g.ObjectId))
        //        .ToList();
        //}

        public async Task<string> GetMemberObjects()
        {
            var client = new HttpClient();
            var queryString = HttpUtility.ParseQueryString(string.Empty);

            /* OAuth2 is required to access this API. For more information visit:
               https://msdn.microsoft.com/en-us/office/office365/howto/common-app-authentication-tasks */



            // Specify values for optional parameters, as needed
            queryString["api-version"] = "1.6";
            var uri = "https://graph.windows.net/me/getMemberObjects?" + queryString;
            StringContent stringContent = new StringContent(
                "{ \"securityEnabledOnly\": false }",
                UnicodeEncoding.UTF8,
                "application/json");
            var response = await client.PostAsync(uri, stringContent);
            //var response = await client.GetAsync(uri);

            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> GetGroupNameByIdAsync(string groupId)
        {
            //using (var client = new HttpClient())
            //{
            //    var queryString = HttpUtility.ParseQueryString(string.Empty);
            //    /* OAuth2 is required to access this API. For more information visit:
            //    https://msdn.microsoft.com/en-us/office/office365/howto/common-app-authentication-tasks */
            //    var api_version = "1.6";
            //    var tenantDomainName = "tenant.onmicrosoft.com";
            //    var uri = String.Format("https://graph.windows.net/{0}/groups/{1}?{2}", tenantDomainName, groupId, api_version);
            //    var response = await client.GetAsync(uri);
            //    return await response.Content.ReadAsStringAsync();
            //}



            //var groupLookupTask = ADGraphClient.Groups.Where(
            //    g => g.ObjectId.Equals(
            //        groupId, StringComparison.CurrentCultureIgnoreCase)).ExecuteSingleAsync();
            //var group = await groupLookupTask;
            //return group.DisplayName;

            Group groupObject = null;
            try
            {
                groupObject = (Group)await ADGraphClient.Groups.GetByObjectId(groupId).ExecuteAsync();
                return groupObject.DisplayName;
            }
            catch (Exception exception)
            {
                throw exception;
            }
        }

        public GraphClient(string serviceRootURL)
        {
            // serviceRootURL = "https://graph.windows.net/85c96496-fbc6-4bf3-bfcc-fb51ca874527";
            Uri serviceRoot = new Uri(serviceRootURL);
            adClient = new ActiveDirectoryClient(
                serviceRoot,
                async () => await GetAppTokenAsync());

        }

        private async Task<string> GetAppTokenAsync()
        {
            // *****ADAL code
            Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult tokenResult = null;
            string userObjectID = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
            Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext authContext =
                new Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext(authority, false);
            Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential credential =
                new Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential(clientId, appKey);
            tokenResult = await authContext.AcquireTokenAsync(resAzureGraphAPI, credential);
            return tokenResult.AccessToken;
        }

        private readonly ActiveDirectoryClient adClient;
        private ActiveDirectoryClient ADGraphClient { get { return adClient; } }
    }
}