namespace AuthServerNet5Identity
{
    using System;
    using System.Threading.Tasks;
    using Config;
    using Identity;
    using Microsoft.AspNet.Builder;
    using Microsoft.AspNet.Hosting;
    using Microsoft.AspNet.Http;
    using Microsoft.AspNet.Identity;
    using Microsoft.Data.Entity;
    using Microsoft.Framework.Configuration;
    using Microsoft.Framework.DependencyInjection;
    using Microsoft.Framework.Logging;
    using Microsoft.Framework.OptionsModel;
    using Microsoft.Framework.Runtime;
    using Thinktecture.IdentityManager;
    using Thinktecture.IdentityManager.Configuration;
    using Thinktecture.IdentityServer.Core.Configuration;
    using Thinktecture.IdentityServer.Core.Services;
    using Thinktecture.IdentityServer.Core.Services.InMemory;
    using LogLevel = Microsoft.Framework.Logging.LogLevel;

    public class Startup
    {
        public IConfiguration Configuration { get; set; }

        public Startup( IHostingEnvironment env, IApplicationEnvironment appEnv )
        {
            var builder = new ConfigurationBuilder( appEnv.ApplicationBasePath )
                .AddJsonFile( "config.json" )
                .AddJsonFile( $"config.{env.EnvironmentName}.json", true );

            if ( env.IsDevelopment() )
            {
                builder.AddUserSecrets();
            }

            builder.AddEnvironmentVariables();

            Configuration = builder.Build();
        }

        public void ConfigureServices( IServiceCollection services )
        {
            services.AddCertificateService();
            services.Configure<CertificateServiceOptions>( Configuration.GetConfigurationSection( "SignatureCert" ) );

            services.AddDataProtection();
            services.AddEntityFramework()
                    .AddSqlServer()
                    .AddDbContext<UserContext>(
                        o => { o.UseSqlServer( Configuration["Data:DefaultConnection:ConnectionString"] ); } );
            services.AddTransient<UserManager<ApplicationUser>>();
            services.AddTransient<RoleManager<ApplicationRole>>();
            services.AddTransient<IUserStore<ApplicationUser>, ApplicationUserStore>();
            services.AddTransient<IRoleStore<ApplicationRole>, ApplicationRoleStore>();
            services.AddIdentity<ApplicationUser, ApplicationRole>(
                o => {
                    o.User = new UserOptions {
                        RequireUniqueEmail = true,
                        UserNameValidationRegex = @"[a-z0-9åäö]{3,50}"
                    };
                } )
                    .AddEntityFrameworkStores<UserContext, int>()
                    .AddDefaultTokenProviders();
            services.AddTransient(
                p => new ApplicationUserService( p.GetRequiredService<UserManager<ApplicationUser>>() ) );
            services.AddTransient(
                p => new ApplicationIdentityManagerService(
                    p.GetRequiredService<UserManager<ApplicationUser>>(),
                    p.GetRequiredService<RoleManager<ApplicationRole>>(),
                    p.GetRequiredService<IOptions<IdentityOptions>>()
                    )
                );
        }

        public void Configure( IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerfactory, IApplicationEnvironment appEnv )
        {
            loggerfactory.AddConsole( LogLevel.Information );
            loggerfactory.AddTraceLogger( LogLevel.Information );

            if ( env.IsDevelopment() )
            {
                app.UseErrorPage();
            }

            app.Map(
                "/identity",
                identity => {
                    var scopeStore = new InMemoryScopeStore( Scopes.Get() );
                    var clientStore = new InMemoryClientStore( Clients.Get() );
                    var factory = new IdentityServerServiceFactory {
                        ScopeStore = new Thinktecture.IdentityServer.Core.Configuration.Registration<IScopeStore>( scopeStore ),
                        ClientStore = new Thinktecture.IdentityServer.Core.Configuration.Registration<IClientStore>( clientStore )
                    };
                    factory.Register(
                        new Thinktecture.IdentityServer.Core.Configuration.Registration<IServiceProvider>(
                            resolver => app.ApplicationServices ) );
                    factory.UserService =
                        new Thinktecture.IdentityServer.Core.Configuration.Registration<IUserService>(
                            resolver => app.ApplicationServices.GetRequiredService<ApplicationUserService>() );

                    var signCert = app.ApplicationServices.GetRequiredService<ICertificateService>().Get();

                    var serverOptions = new IdentityServerOptions {
                        Factory = factory,
                        SiteName = "My Identity Server",
                        SigningCertificate = signCert,
                        RequireSsl = !env.IsDevelopment()
                    };

                    identity.UseIdentityServer( serverOptions );
                } );

            app.Map(
                "/admin",
                admin => {
                    var factory = new IdentityManagerServiceFactory {
                        IdentityManagerService =
                            new Thinktecture.IdentityManager.Configuration.Registration<IIdentityManagerService>(
                                resolver =>
                                    app.ApplicationServices.GetRequiredService<ApplicationIdentityManagerService>() )
                    };
                    admin.UseIdentityManager(
                        new IdentityManagerOptions {
                            Factory = factory,
                            SecurityMode = SecurityMode.LocalMachine,
                            AdminRoleName = "Admin"
                        } );
                } );

            app.Run(
                h => {
                    //h.Response.Redirect( "/admin" );
                    //h.Response.StatusCode = 301;
                    h.Response.WriteAsync( "In Root" );
                    return Task.FromResult( 0 );
                } );
        }
    }
}