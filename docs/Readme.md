# Azure-AD-WebApp-WebAPI-OpenIDConnect-DotNet
This is a .NET 4.5 MVC web app that signs Azure AD users in with OpenID Connect and calls a web api using OAuth 2.0 access tokens. It is baselined from 
[Azure Samples](https://github.com/Azure-Samples/active-directory-dotnet-webapp-webapi-openidconnect) repo and includes modifications to support our specific objectives including:

* Sign-in and sign-out
* Role Based Access Control (RBAC)
* User Role claims or group membership
* Handle ADAL token cache using custom distributed cache
* SQL database connectivity from webApp
