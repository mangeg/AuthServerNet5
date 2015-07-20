namespace AuthServerNet5Identity
{
    using System;
    using System.Threading.Tasks;
    using Config;
    using Identity;
    using Microsoft.AspNet.Builder;
    using Microsoft.AspNet.Diagnostics;
    using Microsoft.AspNet.Hosting;
    using Microsoft.AspNet.Identity;
    using Microsoft.Data.Entity;
    using Microsoft.Framework.Configuration;
    using Microsoft.Framework.DependencyInjection;
    using Microsoft.Framework.Logging;
    using Microsoft.Framework.OptionsModel;
    using Microsoft.Framework.Runtime;
    using Thinktecture.IdentityManager;
    using Thinktecture.IdentityServer.Core.Configuration;
    using Thinktecture.IdentityServer.Core.Services;
    using Thinktecture.IdentityServer.Core.Services.InMemory;

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
            services.AddCertificateService();
            services.Configure<CertificateServiceOptions>( Configuration.GetConfigurationSection( "SignatureCert" ) );
            services.AddEntityFramework()
                .AddSqlServer()
                .AddDbContext<UserContext>(
                    o => { o.UseSqlServer( Configuration["Data:DefaultConnection:ConnectionString"] ); } );
            services.AddTransient<UserManager<ApplicationUser>>();
            services.AddTransient<RoleManager<ApplicationRole>>();
            services.AddTransient<IUserStore<ApplicationUser>, ApplicationUserStore>();
            services.AddTransient<IRoleStore<ApplicationRole>, ApplicationRoleStore>();
            services.AddIdentity<ApplicationUser, ApplicationRole>(
                o =>
                {
                    o.User = new UserOptions {
                        RequireUniqueEmail = true,
                        UserNameValidationRegex = @"[a-z0-9åäö]{3,50}"
                    };
                })
                .AddEntityFrameworkStores<UserContext, int>()
                .AddDefaultTokenProviders();
            services.AddTransient(
                p => new UserService<ApplicationUser, int>( p.GetRequiredService<UserManager<ApplicationUser>>() ) {                    
                } );
            services.AddTransient(
                p => new SimpleIdentityManagerService<ApplicationUser, int, ApplicationRole, int>(
                    p.GetRequiredService<UserManager<ApplicationUser>>(),
                    p.GetRequiredService<RoleManager<ApplicationRole>>(),
                    p.GetRequiredService<IOptions<IdentityOptions>>()
                    ) {
                    } );
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
                identity =>
                {
                    var scopeStore = new InMemoryScopeStore( Scopes.Get() );
                    var clientStore = new InMemoryClientStore( Clients.Get() );
                    var factory = new IdentityServerServiceFactory();
                    factory.ScopeStore = new Registration<IScopeStore>( scopeStore );
                    factory.ClientStore = new Registration<IClientStore>( clientStore );
                    factory.Register( new Registration<IServiceProvider>( resolver => app.ApplicationServices ) );
                    factory.UserService =
                        new Registration<IUserService>( resolver => app.ApplicationServices.GetRequiredService<UserService<ApplicationUser, int>>() ) { };

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
                admin =>
                {
                    var factory = new Thinktecture.IdentityManager.Configuration.IdentityManagerServiceFactory();
                    factory.IdentityManagerService = new Thinktecture.IdentityManager.Configuration.Registration<IIdentityManagerService>(
                        resolver =>
                            app.ApplicationServices.GetRequiredService<SimpleIdentityManagerService<ApplicationUser, int, ApplicationRole, int>>(
                                ) );
                    admin.UseIdentityManager(
                        new Thinktecture.IdentityManager.Configuration.IdentityManagerOptions {
                            Factory = factory,
                            SecurityMode = Thinktecture.IdentityManager.Configuration.SecurityMode.LocalMachine,
                            AdminRoleName = "Admin"
                        } );
                } );

            app.Run(
                h =>
                {
                    h.Response.Redirect( "/admin" );
                    h.Response.StatusCode = 301;
                    return Task.FromResult( 0 );
                } );
        }
    }
}
