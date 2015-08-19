namespace MvcClient
{
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IdentityModel.Tokens;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Authentication.OpenIdConnect;
    using Microsoft.AspNet.Builder;
    using Microsoft.AspNet.Hosting;
    using Microsoft.Framework.DependencyInjection;
    using Microsoft.Framework.Runtime;
    using Newtonsoft.Json.Linq;

    public class Startup
    {
        public void ConfigureServices( IServiceCollection services )
        {
            services.AddMvc().ConfigureMvc( mvcOpts => { } );

            /*services.Configure<ExternalAuthenticationOptions>( options =>
            {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            } );*/
        }

        public void Configure( IApplicationBuilder app, IHostingEnvironment env, IApplicationEnvironment appEnv )
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();
            
            app.UseCookieAuthentication( options =>
            {
                options.AutomaticAuthentication = true;
            } );

            if ( env.IsDevelopment() )
            {
                app.UseErrorPage();
            }

            app.UseOpenIdConnectAuthentication(
                o =>
                {
                    o.AutomaticAuthentication = true;
                    o.Authority = "https://login.local/identity";
                    o.ClientId = "mvc6Hybrid";
                    o.RedirectUri = "http://localhost:14567/";
                    o.ResponseType = "code id_token token";
                    o.Scope = "openid email profile";
                    o.SignInScheme = "Cookies";
                    o.Notifications = new OpenIdConnectAuthenticationNotifications {
                        SecurityTokenValidated = n =>
                        {
                            if ( !string.IsNullOrEmpty( n.ProtocolMessage.IdToken ) )
                            {
                                var sToken = (JwtSecurityToken)new JwtSecurityTokenHandler().ReadToken( n.ProtocolMessage.IdToken );
                                Trace.WriteLine( "ID Token:" );
                                Trace.WriteLine( JToken.Parse( sToken.Header.SerializeToJson() ) );
                                Trace.WriteLine( JToken.Parse( sToken.Payload.SerializeToJson() ) );
                            }
                            if ( !string.IsNullOrEmpty( n.ProtocolMessage.AccessToken ) )
                            {
                                var sToken = (JwtSecurityToken)new JwtSecurityTokenHandler().ReadToken( n.ProtocolMessage.AccessToken );
                                Trace.WriteLine( "Access Token:" );
                                Trace.WriteLine( JToken.Parse( sToken.Header.SerializeToJson() ) );
                                Trace.WriteLine( JToken.Parse( sToken.Payload.SerializeToJson() ) );
                            }

                            return Task.FromResult( 0 );
                        },
                        AuthorizationCodeReceived = n => Task.FromResult( 0 ),
                        MessageReceived = n => Task.FromResult( 0 ),
                        SecurityTokenReceived = n => Task.FromResult( 0 ),
                        RedirectToIdentityProvider = n => Task.FromResult( 0 )
                    };
                } );

            app.UseMvc(
                routes =>
                {
                    routes.MapRoute(
                        "default",
                        "{controller}/{action}/{id?}",
                        new { controller = "Home", action = "Index" } );
                } );
        }
    }
}
