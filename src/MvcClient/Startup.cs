namespace MvcClient
{
    using System;
    using System.Diagnostics;
    using System.Security.Cryptography.X509Certificates;
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
                    o.ResponseType = "code id_token token";
                    o.Scope = "openid email profile";

                    o.SignInScheme = "Cookies";
                    o.Notifications = new OpenIdConnectAuthenticationNotifications {
                        SecurityTokenValidated = n =>
                        {
                            var sToken = new System.IdentityModel.Tokens.JwtSecurityTokenHandler().ReadToken( n.ProtocolMessage.IdToken );

                            var parts = n.ProtocolMessage.IdToken.Split( '.' );
                            var header = Uri.UnescapeDataString( parts[0] );
                            var claims = Uri.UnescapeDataString( parts[1] );
                            var signature = Uri.UnescapeDataString( parts[2] );
                            var signatureCert = new X509Certificate2( Base64Url.Decode( signature ) );
                            var headerJ = JObject.Parse( Encoding.UTF8.GetString( Convert.FromBase64String( header ) ) );
                            var claimsJ = JObject.Parse( Encoding.UTF8.GetString( Convert.FromBase64String( claims ) ) );
                            Trace.WriteLine( "Id token:" );
                            Trace.WriteLine( headerJ );
                            Trace.WriteLine( claimsJ );

                            parts = n.ProtocolMessage.AccessToken.Split( '.' );
                            header = Uri.UnescapeDataString( parts[0] );
                            claims = Uri.UnescapeDataString( parts[1] );
                            signature = Uri.UnescapeDataString( parts[2] );
                            signatureCert =
                                new X509Certificate2( Convert.FromBase64String( signature.Replace( "_", "/" ).Replace( "-", "+" ) ) );
                            headerJ = JObject.Parse( Encoding.UTF8.GetString( Convert.FromBase64String( header ) ) );
                            claimsJ = JObject.Parse( Encoding.UTF8.GetString( Convert.FromBase64String( claims ) ) );
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
            string s = Convert.ToBase64String( arg ); // Standard base64 encoder

            s = s.Split( '=' )[0]; // Remove any trailing '='s
            s = s.Replace( '+', '-' ); // 62nd char of encoding
            s = s.Replace( '/', '_' ); // 63rd char of encoding

            return s;
        }

        public static byte[] Decode( string arg )
        {
            string s = arg;
            s = s.Replace( '-', '+' ); // 62nd char of encoding
            s = s.Replace( '_', '/' ); // 63rd char of encoding

            switch ( s.Length % 4 ) // Pad with trailing '='s
            {
            case 0: break; // No pad chars in this case
            case 2: s += "=="; break; // Two pad chars
            case 3: s += "="; break; // One pad char
            default: throw new Exception( "Illegal base64url string!" );
            }

            return Convert.FromBase64String( s ); // Standard base64 decoder
        }
    }
}
