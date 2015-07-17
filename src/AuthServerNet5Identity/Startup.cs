namespace AuthServerNet5Identity
{
    using System.Threading.Tasks;
    using Config;
    using Microsoft.AspNet.Builder;
    using Microsoft.AspNet.Diagnostics;
    using Microsoft.AspNet.Hosting;
    using Microsoft.Framework.Configuration;
    using Microsoft.Framework.DependencyInjection;
    using Microsoft.Framework.Logging;
    using Microsoft.Framework.Runtime;
    using Thinktecture.IdentityServer.Core.Configuration;

    public class Startup
    {
        public IConfiguration Configuration { get; set; }

        public Startup( IHostingEnvironment env, IApplicationEnvironment appEnv )
        {
            var config = new ConfigurationBuilder( appEnv.ApplicationBasePath )
                .AddJsonFile( "config.json" )
                .AddJsonFile( $"config.{env.EnvironmentName}.json", true );

            config.AddEnvironmentVariables();

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
            services.AddTransient<ICertificateService, CertificateService>();
        }

        public void Configure( IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerfactory )
        {
            loggerfactory.AddConsole( LogLevel.Information );
            loggerfactory.AddTraceLogger( LogLevel.Information );

            if ( env.IsDevelopment() )
            {
                app.UseErrorPage( ErrorPageOptions.ShowAll );
            }

            app.Map(
                "/identity",
                identity => {
                    var factory = InMemoryFactory.Create( Users.Get(), Clients.Get(), Scopes.Get() );

                    var signCert = app.ApplicationServices.GetRequiredService<ICertificateService>().Get();

                    var serverOptions = new IdentityServerOptions
                    {
                        Factory = factory,
                        SiteName = "My Identity Server",
                        SigningCertificate = signCert,
                        RequireSsl = true//env.IsDevelopment()
                    };

                    identity.UseIdentityServer( serverOptions );
                } );

            app.Run( h => {
                h.Response.Redirect( "/identity" );
                h.Response.StatusCode = 301;
                return Task.FromResult( 0 );
            } );
        }
    }
}
