using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;

namespace TodoListWebApp.App_Start
{
    // http://katanaproject.codeplex.com/wikipage?title=System.Web%20response%20cookie%20integration%20issues&referringTitle=Documentation
    public class SystemWebCookieManager : ICookieManager
    {

        public void AppendResponseCookie(Microsoft.Owin.IOwinContext context, string key, string value, Microsoft.Owin.CookieOptions options)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            var webContext = context.Get<HttpContextBase>(typeof(HttpContextBase).FullName);

            bool domainHasValue = !string.IsNullOrEmpty(options.Domain);
            bool pathHasValue = !string.IsNullOrEmpty(options.Path);
            bool expiresHasValue = options.Expires.HasValue;

            var cookie = new HttpCookie(key, value);
            if (domainHasValue)
            {
                cookie.Domain = options.Domain;
            }

            if (pathHasValue)
            {
                cookie.Path = options.Path;
            }

            if (expiresHasValue)
            {
                cookie.Expires = options.Expires.Value;
            }

            if (options.Secure)
            {
                cookie.Secure = true;
            }

            if (options.HttpOnly)
            {
                cookie.HttpOnly = true;
            }

            webContext.Response.AppendCookie(cookie);
        }

        public void DeleteCookie(Microsoft.Owin.IOwinContext context, string key, Microsoft.Owin.CookieOptions options)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            AppendResponseCookie(
                context, key,
                string.Empty,
                new CookieOptions
                {
                    Path = options.Path,
                    Domain = options.Domain,
                    Expires = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                });
        }

        public string GetRequestCookie(Microsoft.Owin.IOwinContext context, string key)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            var webContext = context.Get<HttpContextBase>(typeof(HttpContextBase).FullName);
            var cookie = webContext.Request.Cookies[key];
            return cookie == null ? null : cookie.Value;
        }
    }
}
