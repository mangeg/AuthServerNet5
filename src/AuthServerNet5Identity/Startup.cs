namespace AuthServerNet5Identity
{
    using Microsoft.AspNet.Builder;
    using Microsoft.AspNet.Hosting;
    using Microsoft.AspNet.Http;
    using Microsoft.Framework.Configuration;
    using Microsoft.Framework.DependencyInjection;
    using Microsoft.Framework.Logging;
    using Microsoft.Framework.Runtime;

    public class Startup
    {
        public Startup( IHostingEnvironment env, IApplicationEnvironment appEnv )
        {
            var config = new ConfigurationBuilder( appEnv.ApplicationBasePath )
                .AddJsonFile( "config.json" )
                .AddJsonFile( $"config.{env.EnvironmentName}.json", true );

            Configuration = config.Build();
        }

        public void ConfigureServices( IServiceCollection services )
        {
        }

        public void Configure( IApplicationBuilder app, ILoggerFactory loggerfactory )
        {
            loggerfactory.AddConsole( LogLevel.Information );
            app.Run( async ( context ) => {
                var text = Configuration.Get( "Text" );
                await context.Response.WriteAsync( $"Hello World! {text}" );
            } );
        }

        public IConfiguration Configuration { get; set; }
    }
}
