using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.Framework.DependencyInjection;

namespace MvcClient
{
    public class Startup
    {
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc().ConfigureMvc( mvcOpts => {
            } );
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseCookieAuthentication( o => {
                o.AuthenticationScheme = "Cookies";
            } );
            app.UseOpenIdConnectAuthentication( o => {
                o.Authority = "https://as.local/identity";
                o.ClientId = "mvc6";
                o.RedirectUri = "http://localhost:14567/";
                o.Scope = "openid profile roles";
                o.ResponseType = "id_token token";
                o.UseTokenLifetime = false;
                o.SignInScheme = "Cookies";

                o.Notifications = new Microsoft.AspNet.Authentication.OpenIdConnect.OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = n => {
                        return Task.FromResult( 0 );
                    },
                    RedirectToIdentityProvider = n => {
                        return Task.FromResult( 0 );
                    },
                    SecurityTokenReceived = n => {
                        return Task.FromResult( 0 );
                    }
                };
            } );

            app.UseMvc( routes => {
                routes.MapRoute( "default",
                    "{controller}/{action}/{id?}",
                    defaults: new { controller = "Home", action = "Index" } );
            } );
        }
    }
}
