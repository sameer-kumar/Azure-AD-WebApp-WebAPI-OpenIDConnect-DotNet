# Azure-AD-WebApp-WebAPI-OpenIDConnect-DotNet
I had lots of stumbling blocks while developing a POC for our internal LOB web applications. It had lots of moving parts and took me few weeks to figure out a right way of doing things. That's when the idea for this post cropped up with the assumption of helping others in saving their time and energy. 

With our journey to Azure, I was given a responsibility to develop a POC to vet out a viable security model to be used with Azure PaaS web apps. There were few facts known to me before I started this POC like:
 1. All our current internal LOB web apps are secured using Windows Authentication.
 2. IIS app pools which host our LOB web runs with service account identity.
 3. We sync Azure Active Directory (AAD) with our on-premise AD except for passwords.
 4. [Ping Federate](https://www.pingidentity.com/en/products/pingfederate.html) (not ADFS) is our Federation provider.
 5. Ping configured in our environment uses WS-Federation protocol.

The objectives which we had in mind to prove out with this Azure app service POC were:
 1. Application users should be able to sign-in and sign-out using their domain id (lab environment). They don't need to specify their password credentials as Ping is configured to allow single sign-on.
 2. Should be able to support RBAC.
 3. Should be able to retrieve group membership and assert User IsInRole() for authorizing protected web resources.
 4. Should be able to handle ADAL token cache using custom distributed cache.
 5. Should be able to connect to application SQL database

 In my initial days of POC, I was overwhelmed with the information available to me. It wasn’t until I read Dave's [blog](https://blogs.technet.microsoft.com/askpfeplat/2014/11/02/adfs-deep-dive-comparing-ws-fed-saml-and-oauth/) that my understanding of security protocols and federation finally started to crystalize. Once I gained a solid foot on this, a struggle started for finding who's who e.g. what's the role of AAD in our Azure PaaS web apps, how Ping is related etc. Deciding upon the right protocol for us was another hump. Ping configured in our environment uses WS-Fed protocol so shall we use this or OpenID, OAuth, or any other [prescribed](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-authentication-protocols) by Azure. It is not until I tried out various Azure [samples](https://github.com/Azure-Samples), lots of google reading and burnt up my MSDN Azure hours that I was able to connect the dots. So I figured two vital roles played by AAD are that of an Identity provider and STS for your Azure web app. Secondly, it didn't matter how we configured Ping in our environment except for a key thing which is trust between Azure and Ping. So, the choice of sign-in protocol is neutral hence we went with MS recommended [OpenID](http://openid.net/specs/openid-connect-core-1_0.html).

With this foundation laid out, my POC started weaning out based off Azure OpenID [sample](https://github.com/Azure-Samples/active-directory-dotnet-webapp-webapi-openidconnect). Let's see how my final POC met the specified objectives:
 1. Ability to sign-in and sign-out
 
     a. Setup and configure following AAD applications which would be associated with Azure web app. You may refer steps mentioned in [step 2](https://github.com/Azure-Samples/active-directory-dotnet-webapp-webapi-openidconnect#step-2--register-the-sample-with-your-azure-active-directory-tenant).
         
         * Details of AAD app associated with web app:
		   Name: Raft-ADFS-Test-02
		   App ID URI: https://{tenantName}/Raft-ADFS-Test-02
           Home page URL: https://raftadfstest2.azurewebsites.net/
           Logout URL: https://raftadfstest2.azurewebsites.net/Account/EndSession
           Application Type: Web app / API
           Multi-tenant: No
           Reply URLs: https://raftadfstest2.azurewebsites.net/
           Owners: None
           Permissions:
             Windows Azure AD:
               Application Permissions: Read directory data
               Delegated Permissions: Sign in and read user profile
            Raft-Adfs-Service-03:
              Application Permissions: None
              Delegated Permissions: Access raft-adfs-service-03

         * Details of AAD app associated with web api:
         Name: Raft-ADFS-Service-03
         App ID URI: https://{tenantName}/Raft-ADFS-Service-03
         Home page URL: https://raftsampleservice2.azurewebsites.net
         Logout URL: None
         Application Type: Web app / API
         Multi-tenant: No
         Reply URLs: https://raftsampleservice2.azurewebsites.net/
         Owners: None
         Permissions:
           Windows Azure AD:
             Delegated Permissions: Sign in and read user profile  

     b. Configure the sample app to use your Azure AD tenant. Follow [step 3](https://github.com/Azure-Samples/active-directory-dotnet-webapp-webapi-openidconnect#step-3--configure-the-sample-to-use-your-azure-ad-tenant) of original article.

        | key  | value  | notes  |   |
|:-----|:-------|:-------|---|
ida:GraphResourceId  |https://graph.windows.net    |Azure GraphApi standard resource URL. |   |

        <table border="1" style="width:300px">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                    <th>Notes</th>
                </tr>
            </thead>
            <tbody>
            <tr>
                <td>ida:GraphResourceId</td>
                <td>https://graph.windows.net</td>
                <td>Azure GraphApi standard resource URL.</td>
            </tr>
            <tr>
                <td>ida:GraphUserUrl</td>
                <td>https://graph.windows.net/{0}/me?api-version=2013-11-08</td>
                <td>Azure GraphApi resource URL for current logged on user. It's the latest version as of this day so may change in future.</td>
            </tr>
            <tr>
                <td>todo:TodoListResourceid</td>
                <td>https://{tenantName}/raft-adfs-service-03</td>
                <td>App Id URI of the AAD app associated with web api app.</td>
            </tr>
            <tr>
                <td>todo:TodoListBaseAddress</td>
                <td>https://raftsampleservice2.azurewebsites.net</td>
                <td>URL of Web Api hosted on Azure</td>
            </tr>
            <tr>
                <td>ida:ClientId</td>
                <td>{guid}</td>
                <td>Application ID of AAD app (raft-adfs-test-02) associated with web app</td>
            </tr>
            <tr>
                <td>ida:AppKey</td>
                <td>{secretHash}</td>
                <td>Key (generated from Azure portal) associated with raft-adfs-test-02 AAD app.</td>
            </tr>
            <tr>
                <td>ida:Tenant</td>
                <td>{tenantName}</td>
                <td>FQDN of Azure AD tenant</td>
            </tr>
            <tr>
                <td>ida:AADInstance</td>
                <td>https://login.microsoftonline.com/{0}</td>
                <td>Constructed at run time in application startup.</td>
            </tr>
            <tr>
                <td>ida:RedirectUri</td>
                <td>https://raftadfstest2.azurewebsites.net/</td>
                <td>Reply URL configured for raft-adfs-test-02 AAD app. Don't ignore trailing slash at end. Must match with what configured from portal.</td>
            </tr>
            <tr>
                <td>ida:RedisEndpoint</td>
                <td>raftCache.redis.cache.windows.net</td>
                <td>Host name of redis cache used</td>
            </tr>
            <tr>
                <td>ida:RedisAccessKey</td>
                <td>{hash}</td>
                <td>Primary access key associated with redis cache instance used.</td>
            </tr>
            <tr>
                <td>ida:CertName</td>
                <td>CN=sqlAuthTestToken</td>
                <td>Name of (self-signed) certificate uploaded to web app. This is needed if we are not using password for SPN but certificate. This SPN is associated with Raft-ADFS-Sql-03 AAD app for SQL authentication. So either use this or ida:ClientSecretSqlAadApp key.</td>
            </tr>
            <tr>
                <td>ida:ClientIdSqlAadApp</td>
                <td>{guid}</td>
                <td>Application ID of AAD app (Raft-ADFS-Sql-03) created for SQL authentication via SPN mode.</td>
            </tr>
            <tr>
                <td>ida:ClientSecretSqlAadApp</td>
                <td>{password}</td>
                <td>Secret key associated with SPN of AAD app (Raft-ADFS-Sql-03) created for SQL authentication.</td>
            </tr>
            <tr>
                <td>sqldb:ResourceId</td>
                <td>https://database.windows.net/</td>
                <td>Azure SQL DB resource URL. It's standard.</td>
            </tr>
        </tbody>
        </table>

     c. The sample code didn't work out of box for me. I need to downgrade ADAL the version 3.9.304210845 from 3.13.8 to fix the issues. Once done, the flow was straight forward. It uses Owin Middleware Component for OpenID connect. The "Sign in" link takes the user to login.microsoftonline.com screen where they enter their domain login id, Ping validates the user, AAD trusts Ping hence issues authentication token which is stored as a cookie in the browser.

     d. There is a peculiar behavior about the provided sample app although intermittent but worth mentioning as I put a workaround in there. This issue occurs on initial login, when a redirect loop occurs between the app and the AAD login. This seemed to be session-specific as it didn't not occur for all users at once. Once the redirect loop occurs it seems to continue occurring until an application pool refresh. This issue is well known as acknowledged [here](http://katanaproject.codeplex.com/wikipage?title=System.Web%20response%20cookie%20integration%20issues&referringTitle=Documentation) by the team. 

 2. Ability for Role Based Access Control (RBAC)

     Using RBAC, you can grant only the amount of access that users need to perform their jobs.
     Our POC Web application is protected via claims-based identity. And this application occasionally reaches out to a backend service (webApi), and that the service output (or even the ability of calling the service to begin with) depends on the current user of the Web application. So we have a need to flow identity through the layers of our solution.

     Azure supports two identity types for authentication to make calls to webApi from webApp.
     * Application identity: This scenario uses OAuth 2.0 client credentials grant to authenticate as the application and access the web API. When using an application identity, the web API can only detect that the web application is calling it, as the web API does not receive any information about the user. If the application receives information about the user, it will be sent via the application protocol, and it is not signed by Azure AD. The web API trusts that the web application authenticated the user. For this reason, this pattern is called a trusted subsystem.

     * Delegated user identity: This scenario can be accomplished in two ways: OpenID Connect, and OAuth 2.0 authorization code grant with a confidential client. The web application obtains an access token for the user, which proves to the web API that the user successfully authenticated to the web application and that the web application was able to obtain a delegated user identity to call the web API. This access token is sent in the request to the web API, which authorizes the user and returns the desired resource. This is similar to conventional [ActAs](https://blogs.msdn.microsoft.com/vbertocci/2008/09/07/delegation-or-traversing-multilayer-architectures/) approach.
     The idea behind the Delegated user identity approach to the problem is pretty simple: when it needs to call the backend service, the Web application requests a token to the STS (AAD) by presenting both its own application credentials and the token that the user presented in order to authenticate with the Web app itself (commonly referred to as the bootstrap token). The STS can then verify that the request is actually coming from the (well-known) Web application, and verify that the user is actually engaging with the Web app at the moment; hence, the STS can apply whatever logic it deems appropriate to manufacture (or not) a token that will fully reflect the situation (claims about the user, etc) and that is scoped precisely to the backend service.
     That is a fantastic way of handling delegation through solution layers, far more robust and expressive than the classic trusted subsystem approach. This also works well in cases (if any), where frontend and backend are operated by different & distinct owners.

     You can read about these supported identity models with their complete flow [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-authentication-scenarios).

     Objectives specified with our POC were achieved with Delegate user identity model. Look at this [segment](https://github.com/Azure-Samples/active-directory-dotnet-webapp-webapi-openidconnect/blob/master/TodoListWebApp/Controllers/UserProfileController.cs#L60-L64) or [this](https://github.com/Azure-Samples/active-directory-dotnet-webapp-webapi-openidconnect/blob/master/TodoListWebApp/Controllers/TodoListController.cs#L55-L66). 

 3. User Role claims or group membership

    Another objective for our POC application is the ability to make authorization decisions based on a user’s membership in a specific security group (or groups). We can take advantage of Azure Active Directory to do just that. You can look for it in the Claims collection for the authenticated user provided you enable the group claims feature for your application in Azure AD.
    Enabling the group claims feature currently requires that you update the manifest for the application in Azure AD. In the Azure portal I’ll begin by going to the SETTINGS page for the Raft-ADFS-Test-02 application in Azure AD. At the top of the page is a MANIFEST button where I can preview the manifest for the Raft-ADFS-Test-02 (web) application. The application manifest is just a JSON file. Scrolling down the manifest file I will find the **groupMembershipClaims** property which will be set to null. I’m going to change this value to **SecurityGroup** and then save the changes. Save your changes by clicking Save button at the top. Now if you run POC application under the debugger, you can see the new group claims in the claims collection. The group claims feature in Azure AD is transitive. So, if a user is a member of a group say G1 and G1 group is a member of G2 group, the user is a member of both security groups i.e. G1 and G2.

    More details about application manifest can be found [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-application-manifest) (if you are interested).

    Once I get group membership details, I transform those into [Role](https://msdn.microsoft.com/en-us/library/system.security.claims.claimtypes.role(v=vs.110).aspx) claims using [GraphApi](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-graph-api). This is needed so that we can assert using [IsInRole](https://msdn.microsoft.com/en-us/library/system.web.security.roleprincipal.isinrole(v=vs.110).aspx) in our POC web application. We don't want to carry out this transformation procedure over and over with each web request hence we decided to use Cookie authentication middleware to persist the Role claims in user session after each successful login.

    ```
    app.UseCookieAuthentication(new CookieAuthenticationOptions() {
        CookieSecure = CookieSecureOption.Always,
        Provider = new CookieAuthenticationProvider
        {
            OnResponseSignIn = context => {
                context.Identity = TransformClaims(context, app);
            }

        }
    });

    ```
   
 4. Handle ADAL token cache using custom distributed cache
    
    [ADAL v2](http://www.cloudidentity.com/blog/2014/07/09/the-new-token-cache-in-adal-v2/) uses cache behind the scenes. The sample code available on Azure samples uses NaiveSessionCache which may not work in web farm or load balanced environments. 
    So I added machineKey in web.config file of the web app.

    ```
    <system.web>
        <machineKey validationKey="105E14408F7F5794AA7CB29017D753AFD7EBB58B6040A8CC73D5E66C024DFC2BD2D1A52A62F2AF6696319AE3BDC551FFB070B650D418CAF2BF8FFDF46CA791E8" decryptionKey="C7631DEAE361FB4C792D2D10FC1B2BFCAAB15CCDF6B65D5F8370845E650BE1E3" validation="SHA1" decryption="AES" />
    </system.web>
    ```
    If you are unsure about this section, I would recommend this [MSDN](https://msdn.microsoft.com/en-us/library/ff649308.aspx#paght000007_webfarmdeploymentconsiderations) article.

    Later, we decided to use [Azure Redis Cache](https://azure.microsoft.com/en-us/services/cache/) service instead of web Session cache to meet specified objectives.
    I am also encrypting the user access tokens before storing them in Azure Redis cluster and decrypting them back before handing them over to ADAL.

 5. SQL database connectivity from webApp

    We are leveraging AAD for connecting to Microsoft Azure SQL database. If you want to know the benefits of this approach, read [here](https://docs.microsoft.com/en-us/azure/sql-database/sql-database-aad-authentication).

    Among all the options offered by SQL server security team we chose token based authentication for our POC app. It enables more sophisticated scenarios, including certificate-based authentication. Although, we didn't go for certificate-based model due to the high cost involved (purchase & maintain certs) however we opted for the password-based approach.

    The high level steps mentioned below shows how to obtain an Azure AD authentication token for a user (in Azure AD directory), and use that token for authentication with SQL Database.

    * If you are using cert based SPN, use the following command to generate one:
    
       ```
       c:/"Program Files (x86)/Windows Kits/8.1/bin/x64"/makecert -r -pe -n "CN=mytokentestCert" -ss My -len 2048 mytokentestCert.cer
       ```
       Export the .cer to .pfx either from UI or cmd line.

       More details are available [here](https://msdn.microsoft.com/library/ff699202.aspx).

       You also need to add the cert to your Azure web site via Azure portal or Azure KeyVault.
       Adding a Certificate to your Web App is a simple two-step process. First, go to the Azure Portal and navigate to your Web App. On the Settings blade for your Web App, click on the entry for "SSL certificates". On the blade that opens you will be able to upload the Certificate that you created above, mytokentestCert.pfx, make sure that you remember the password for the pfx.
       The last thing that you need to do is to add an Application Setting to your Web App that has the name WEBSITE_LOAD_CERTIFICATES and a value of *. This will ensure that all Certificates are loaded. If you wanted to load only the Certificates that you have uploaded, then you can enter a comma-separated list of their thumbprints.
       To learn more about adding a Certificate to a Web App, see [Using Certificates in Azure Websites Applications](https://azure.microsoft.com/blog/2014/10/27/using-certificates-in-azure-websites-applications/).

       **Add a Certificate to Key Vault as a secret** Instead of uploading your certificate to the Web App service directly, you can store it in Key Vault as a secret and deploy it from there. This is a two-step process that is outlined in the following blog post, [Deploying Azure Web App Certificate through Key Vault](https://blogs.msdn.microsoft.com/appserviceteam/2016/05/24/deploying-azure-web-app-certificate-through-key-vault/).

    * Register an application in Azure AD (AAD)
       
       Details of AAD app associated with Sql:  
       Name: Raft-ADFS-Sql-03  
       App ID URI: https://{tenantName}/Raft-ADFS-Sql-03  
       Home page URL: https://myspntest1  
       Logout URL: None  
       Application Type: Web app / API  
       Multi-tenant: No  
       Reply URLs: None  
       Owners: None  
       Permissions: None  
       Keys: {secret}  

       I used following PowerShell script (Password Authentication) to generate this AAD app and its SPN.

       ```
       # https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-authenticate-service-principal
       $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate
       $cert.Import("C:\temp\sqlAuthTestToken.cer")
       $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
       
       #Login-AzureRmAccount
       $startDate= [System.DateTime]::Now
       $endDate = $startDate.AddYears(1)

       ########Cert Authentication#################
       #$app = New-AzureRmADApplication -DisplayName "Raft-ADFS-Sql-02" -HomePage "http://mytokentest2" -IdentifierUris "https://{tenantName}/Raft-ADFS-Sql-02" -CertValue $keyValue -EndDate ([datetime]$cert.GetExpirationDateString()) -StartDate ([datetime]$cert.GetEffectiveDateString())
       $app = New-AzureRmADApplication -DisplayName "Raft-ADFS-Sql-02" -HomePage "http://mytokentest2" -IdentifierUris "https://{tenantName}/Raft-ADFS-Sql-02" -CertValue $keyValue -EndDate $endDate -StartDate $startDate
       New-AzureRmADServicePrincipal -ApplicationId $app.ApplicationId
       Start-Sleep 15
       #New-AzureRmRoleAssignment -RoleDefinitionName Reader -ServicePrincipalName $app.ApplicationId

       ########Password Authentication#################
       $app = New-AzureRmADApplication -DisplayName "Raft-ADFS-Sql-03" -HomePage "https://myspntest1" -IdentifierUris "https://{tenantName}/Raft-ADFS-Sql-03" -Password "{secret}" -StartDate $startDate -EndDate $endDate
       New-AzureRmADServicePrincipal -ApplicationId $app.ApplicationId
       ```

    * Add SPN to Azure SQL database

       ```
       CREATE USER [Raft-ADFS-Sql-03]
       FROM EXTERNAL PROVIDER;
       sp_addrolemember 'db_owner', 'Raft-ADFS-Sql-03'
       ```

    * Add Azure SQL Database to the list of APIs which will require permission from your application

       You will need to add Azure SQL Database to the list of APIs / applications which will be granted delegated permission via your application. Failure to do this will result in an error message similar to the following:

       > *“AADSTS65001: The user or administrator has not consented to use the application with ID ‘{your-application-id-here}’. Send an interactive authorization request for this user and resource.”*

       Setting the permission is fairly easy via the Azure portal.
       * Select the newly created application (in this case, it was Raft-ADFS-Sql-03)
       * On the Settings blade, select Required permissions.
       * Add a new required permission and select Azure SQL Database as the API. You’ll want to search for “azure” to get “Azure SQL Database” to appear in the list. Be sure to select the checkbox for “Access Azure SQL DB and Data Warehouse”.

       I should point out that even after adding the delegated permission as shown above, you may still get the previously mentioned error. We’ll solve that next.

    * Consent to allow your application to access Azure SQL Database

       That error you received before about the administrator having not consented to use application is something we need to get past. To do so, you can force a one-time consent dialog so you can consent to your application delegating access to Azure SQL Database. You’ll need to craft a URL in the following format (wrapped for readability):

       ```
       https://login.microsoftonline.com/%5Byour-tenant%5D.onmicrosoft.com/oauth2/authorize
       ?client_id=[your-client-application-id]
       &response_type=id_token&nonce=1234&scope=openid&prompt=admin_consent
       ```
       Paste that URL into your favorite browser window and go. You should be prompted to log into your Azure subscription. Do so as a Global Administrator for your Azure AD tenant.

    * Add the Active Directory Authentication Library (ADAL) to the project via NuGet
    * Add code to obtain an Azure AD authentication token

       You can refer sample code [here](https://github.com/sameer-kumar/Azure-AD-WebApp-WebAPI-OpenIDConnect-DotNet/blob/master/TodoListWebApp/App_Start/TokenFactory.cs#L135-L145).
    * Add code which uses Azure AD authentication token to authenticate with SQL Database

       You can refer sample code [here](https://github.com/sameer-kumar/Azure-AD-WebApp-WebAPI-OpenIDConnect-DotNet/blob/master/TodoListWebApp/Controllers/HomeController.cs#L155-L178).

> At the end there is one confession I like to make that I'm not a security guy and this is my first journey to this whole new Azure paradigm. This could be a reason why it took me longer to figure out some stuff which could have been done sooner.