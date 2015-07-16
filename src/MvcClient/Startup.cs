namespace MvcClient
{
    using System;
    using System.Diagnostics;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Authentication;
    using Microsoft.AspNet.Authentication.Cookies;
    using Microsoft.AspNet.Authentication.OpenIdConnect;
    using Microsoft.AspNet.Builder;
    using Microsoft.Framework.DependencyInjection;
    using Newtonsoft.Json.Linq;

    public class Startup
    {
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices( IServiceCollection services )
        {
            services.AddMvc().ConfigureMvc( mvcOpts => { } );

            services.Configure<ExternalAuthenticationOptions>( options =>
            {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            } );
        }

        public void Configure( IApplicationBuilder app )
        {
            app.UseCookieAuthentication( options =>
            {
                options.AutomaticAuthentication = true;
            } );

            app.UseOpenIdConnectAuthentication(
                o =>
                {
                    o.AutomaticAuthentication = true;
                    o.Authority = "https://as.local/identity";
                    o.ClientId = "mvc6Hybrid";
                    o.RedirectUri = "http://localhost:14567/";
                    o.ResponseType = "code id_token";
                    o.Scope = "openid email profile";

                    o.SignInScheme = "Cookies";
                    o.Notifications = new OpenIdConnectAuthenticationNotifications {
                        SecurityTokenValidated = n =>
                        {
                            var parts = n.ProtocolMessage.IdToken.Split( '.' );
                            var header = parts[0];
                            var claims = parts[1];
                            var headerJ = JObject.Parse(Encoding.UTF8.GetString( Base64Url.Decode( header ) ) );
                            var claimsJ = JObject.Parse( Encoding.UTF8.GetString( Base64Url.Decode( claims ) ) );
                            Trace.WriteLine( "Id token:" );
                            Trace.WriteLine( headerJ );
                            Trace.WriteLine( claimsJ );

                            parts = n.ProtocolMessage.AccessToken.Split( '.' );
                            header = parts[0];
                            claims = parts[1];
                            headerJ = JObject.Parse( Encoding.UTF8.GetString( Base64Url.Decode( header ) ) );
                            claimsJ = JObject.Parse( Encoding.UTF8.GetString( Base64Url.Decode( claims ) ) );
                            Trace.WriteLine( "Access token:" );
                            Trace.WriteLine( headerJ );
                            Trace.WriteLine( claimsJ );
                            return Task.FromResult( 0 );
                        },
                        AuthorizationCodeReceived = n =>
                        {
                            return Task.FromResult( 0 );
                        },
                        MessageReceived = n =>
                        {
                            

                            return Task.FromResult( 0 );
                        },
                        SecurityTokenReceived = n =>
                        {
                            return Task.FromResult( 0 );
                        }
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

    public static class Base64Url
    {
        public static string Encode( byte[] arg )
        {
            return Convert.ToBase64String( arg ).Split( '=' )[0].Replace( '+', '-' ).Replace( '/', '_' );
        }

        public static byte[] Decode( string arg )
        {
            string s = arg.Replace( '-', '+' ).Replace( '_', '/' );
            switch ( s.Length % 4 )
            {
                case 0:
                    return Convert.FromBase64String( s );
                case 2:
                    s += "==";
                    goto case 0;
                case 3:
                    s += "=";
                    goto case 0;
                default:
                    throw new Exception( "Illegal base64url string!" );
            }
        }
    }
}
