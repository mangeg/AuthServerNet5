namespace AuthServerNet5Identity
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Threading.Tasks;
    using Config;
    using Microsoft.AspNet.Builder;
    using Microsoft.AspNet.DataProtection;
    using Microsoft.AspNet.Diagnostics;
    using Microsoft.AspNet.Hosting;
    using Microsoft.AspNet.Http;
    using Microsoft.Framework.Configuration;
    using Microsoft.Framework.DependencyInjection;
    using Microsoft.Framework.Logging;
    using Microsoft.Framework.Logging.Console;
    using Microsoft.Framework.Runtime;
    using Microsoft.Owin.Builder;
    using Owin;
    using Thinktecture.IdentityServer.Core.Configuration;
    using DataProtectionProviderDelegate = System.Func<string[], System.Tuple<System.Func<byte[], byte[]>, System.Func<byte[], byte[]>>>;
    using DataProtectionTuple = System.Tuple<System.Func<byte[], byte[]>, System.Func<byte[], byte[]>>;

    public class Startup
    {
        public IConfiguration Configuration { get; set; }

        public Startup( IHostingEnvironment env, IApplicationEnvironment appEnv )
        {
            Trace.WriteLine( "In startup" );
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
            services.AddTransient<CertificateService>();
        }

        public void Configure( IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerfactory )
        {
            loggerfactory.AddConsole( LogLevel.Information );
            loggerfactory.AddTraceLogger( LogLevel.Information );

            var configLogger = loggerfactory.CreateLogger( "Config" );

            //if ( env.IsDevelopment() )
            {
                app.UseErrorPage( ErrorPageOptions.ShowAll );
            }

            app.Map(
                "/identity",
                identity =>
                {
                    var factory = InMemoryFactory.Create(
                        users: Users.Get(),
                        clients: Clients.Get(),
                        scopes: Scopes.Get() );

                    identity.UseOwin(
                        addToPipeline =>
                        {
                            addToPipeline(
                                next =>
                                {
                                    var builder = new AppBuilder();

                                    var provider = app.ApplicationServices.GetService<IDataProtectionProvider>();
                                    builder.Properties["security.DataProtectionProvider"] = new DataProtectionProviderDelegate(
                                        purposes =>
                                        {
                                            var dataProtection = provider.CreateProtector( string.Join( ",", purposes ) );
                                            return new DataProtectionTuple( dataProtection.Protect, dataProtection.Unprotect );
                                        } );


                                    configLogger.LogInformation( "Getting certificate" );
                                    var signCert = app.ApplicationServices.GetService<CertificateService>().Get();
                                    var serverOptions = new IdentityServerOptions {
                                        Factory = factory,
                                        SiteName = "Scancloud Auth Server",
                                        SigningCertificate = signCert,
                                    };

                                    if ( env.IsDevelopment() )
                                    {
                                        serverOptions.RequireSsl = false;
                                    }

                                    builder.UseIdentityServer( serverOptions );

                                    var appFunc =
                                        builder.Build( typeof( Func<IDictionary<string, object>, Task> ) ) as
                                            Func<IDictionary<string, object>, Task>;

                                    return appFunc;
                                } );
                        } );
                } );

            app.Run(
                async ( context ) =>
                {
                    var text = Configuration.Get( "Text" );
                    await context.Response.WriteAsync( $"Hello World! {text}" );
                } );
        }
    }
}
