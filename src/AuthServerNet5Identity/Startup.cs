namespace AuthServerNet5Identity
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Builder;
    using Microsoft.AspNet.DataProtection;
    using Microsoft.AspNet.Diagnostics;
    using Microsoft.AspNet.Hosting;
    using Microsoft.AspNet.Http;
    using Microsoft.Framework.Configuration;
    using Microsoft.Framework.DependencyInjection;
    using Microsoft.Framework.Logging;
    using Microsoft.Framework.Runtime;
    using Microsoft.Owin.Builder;
    using Owin;
    using Thinktecture.IdentityServer.Core.Configuration;
    using Thinktecture.IdentityServer.Core.Models;
    using Thinktecture.IdentityServer.Core.Services.InMemory;
    using Constants = Thinktecture.IdentityServer.Core.Constants;
    using DataProtectionProviderDelegate = System.Func<string[], System.Tuple<System.Func<byte[], byte[]>, System.Func<byte[], byte[]>>>;
    using DataProtectionTuple = System.Tuple<System.Func<byte[], byte[]>, System.Func<byte[], byte[]>>;

    public class Startup
    {
        public IConfiguration Configuration { get; set; }

        public Startup( IHostingEnvironment env, IApplicationEnvironment appEnv )
        {
            var config = new ConfigurationBuilder( appEnv.ApplicationBasePath )
                .AddJsonFile( "config.json" )
                .AddJsonFile( $"config.{env.EnvironmentName}.json", true );

            if ( env.IsDevelopment() )
            {
                config.AddUserSecrets();
            }

            Configuration = config.Build();
        }

        public void ConfigureServices( IServiceCollection services )
        {
            services.AddDataProtection();
            services.AddSingleton( sp => Configuration );
        }

        public void Configure( IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerfactory, IApplicationEnvironment appEnv )
        {
            loggerfactory.AddConsole( LogLevel.Information );

            if ( env.IsDevelopment() )
            {
                app.UseErrorPage( ErrorPageOptions.ShowAll );
            }

            app.Map( "/identity",
                identity => {

                    var factory = InMemoryFactory.Create(
                                users: Users.Get(),
                                clients: Clients.Get(),
                                scopes: Scopes.Get() );

                    identity.UseOwin( addToPipeline => {
                        addToPipeline( next => {
                            var builder = new AppBuilder();

                            var provider = app.ApplicationServices.GetService<IDataProtectionProvider>();
                            builder.Properties["security.DataProtectionProvider"] = new DataProtectionProviderDelegate( purposes =>
                            {
                                var dataProtection = provider.CreateProtector( string.Join( ",", purposes ) );
                                return new DataProtectionTuple( dataProtection.Protect, dataProtection.Unprotect );
                            } );

                            var passWord = Configuration.Get( "SignatureCert:Password" );
                            var signCert = Certificate.Get( appEnv.ApplicationBasePath, passWord );
                            var serverOptions = new IdentityServerOptions
                            {
                                Factory = factory,
                                SiteName = "Scancloud Auth Server",
                                SigningCertificate = signCert,
                            };

                            if ( env.IsDevelopment() )
                            {
                                serverOptions.RequireSsl = false;
                            }

                            builder.UseIdentityServer( serverOptions );

                            var appFunc = builder.Build( typeof(Func<IDictionary<string, object>, Task>) ) as Func<IDictionary<string, object>, Task>;

                            return appFunc;
                        } );
                    } );
                } );

            app.Run( async ( context ) => {
                var text = Configuration.Get( "Text" );
                await context.Response.WriteAsync( $"Hello World! {text}" );
            } );
        }
    }

    static class Users
    {
        public static List<InMemoryUser> Get()
        {
            var users = new List<InMemoryUser>
            {
                new InMemoryUser{Subject = "818727", Username = "alice", Password = "alice",
                    Claims = new Claim[]
                    {
                        new Claim(Constants.ClaimTypes.Name, "Alice Smith"),
                        new Claim(Constants.ClaimTypes.GivenName, "Alice"),
                        new Claim(Constants.ClaimTypes.FamilyName, "Smith"),
                        new Claim(Constants.ClaimTypes.Email, "AliceSmith@email.com"),
                        new Claim(Constants.ClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
                        new Claim(Constants.ClaimTypes.Role, "Admin"),
                        new Claim(Constants.ClaimTypes.Role, "Geek"),
                        new Claim(Constants.ClaimTypes.WebSite, "http://alice.com"),
                        new Claim(Constants.ClaimTypes.Address, "{ \"street_address\": \"One Hacker Way\", \"locality\": \"Heidelberg\", \"postal_code\": 69118, \"country\": \"Germany\" }")
                    }
                },
                new InMemoryUser{Subject = "88421113", Username = "bob", Password = "bob",
                    Claims = new Claim[]
                    {
                        new Claim(Constants.ClaimTypes.Name, "Bob Smith"),
                        new Claim(Constants.ClaimTypes.GivenName, "Bob"),
                        new Claim(Constants.ClaimTypes.FamilyName, "Smith"),
                        new Claim(Constants.ClaimTypes.Email, "BobSmith@email.com"),
                        new Claim(Constants.ClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
                        new Claim(Constants.ClaimTypes.Role, "Developer"),
                        new Claim(Constants.ClaimTypes.Role, "Geek"),
                        new Claim(Constants.ClaimTypes.WebSite, "http://bob.com"),
                        new Claim(Constants.ClaimTypes.Address, "{ \"street_address\": \"One Hacker Way\", \"locality\": \"Heidelberg\", \"postal_code\": 69118, \"country\": \"Germany\" }")
                    }
                },
            };

            return users;
        }
    }
    public class Clients
    {
        public static List<Client> Get()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientName = "MVC6 Client",
                    Enabled = true,

                    ClientId = "mvc6",
                    Flow = Flows.Implicit,

                    RequireConsent = true,
                    AllowRememberConsent = true,

                    RedirectUris = new List<string>
                    {
                        "http://localhost:14567/"
                    }
                }
            };
        }
    }
    public class Scopes
    {
        public static IEnumerable<Scope> Get()
        {
            return new[]
            {
                StandardScopes.OpenId,
                StandardScopes.Profile,
                StandardScopes.Email,
                StandardScopes.Address,
                StandardScopes.OfflineAccess,
                StandardScopes.RolesAlwaysInclude,
                StandardScopes.AllClaims,

                ////////////////////////
                // resource scopes
                ////////////////////////

                new Scope
                {
                    Name = "read",
                    DisplayName = "Read data",
                    Type = ScopeType.Resource,
                    Emphasize = false,
                },
                new Scope
                {
                    Name = "write",
                    DisplayName = "Write data",
                    Type = ScopeType.Resource,
                    Emphasize = true,
                },
                new Scope
                {
                    Name = "idmgr",
                    DisplayName = "IdentityManager",
                    Type = ScopeType.Resource,
                    Emphasize = true,
                    ShowInDiscoveryDocument = false,

                    Claims = new List<ScopeClaim>
                    {
                        new ScopeClaim(Constants.ClaimTypes.Name),
                        new ScopeClaim(Constants.ClaimTypes.Role)
                    }
                }
            };
        }
    }

    public class Certificate
    {
        public static X509Certificate2 Get( string path, string password )
        {
            var finalPath = Path.Combine( path, "as.local.pfx" );
            return new X509Certificate2( finalPath, password );
        }
    }
}
