namespace AuthServerNet5Identity.Config
{
    using System.IO;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Framework.DependencyInjection;
    using Microsoft.Framework.Logging;
    using Microsoft.Framework.OptionsModel;
    using Microsoft.Framework.Runtime;

    public class CertificateService : ICertificateService
    {
        private readonly IOptions<CertificateServiceOptions> _options;
        private readonly IApplicationEnvironment _appEnv;
        private readonly ILogger _logger;

        public CertificateService( IOptions<CertificateServiceOptions> options, ILoggerFactory loggerFactory, IApplicationEnvironment appEnv )
        {
            _options = options;
            _appEnv = appEnv;
            _logger = loggerFactory.CreateLogger<CertificateService>();
        }

        public X509Certificate2 Get()
        {
            var path = _options.Options.Path;
            var password = _options.Options.Password;

            var fullPath = Path.Combine( _appEnv.ApplicationBasePath, path ?? string.Empty );

            _logger.LogInformation( "Certificate Path: {base}\\{path}", _appEnv.ApplicationBasePath, path ?? "null" );
            _logger.LogInformation( "Certificate Password: {password}", password ?? "null" );

            return new X509Certificate2( fullPath, password );
        }
    }

    public static class CeriticateServiceAppBuilderExtensions
    {
        public static IServiceCollection AddCertificateService( this IServiceCollection services )
        {
            services.Configure<CertificateServiceOptions>( o => { } );
            services.AddTransient<ICertificateService, CertificateService>();
            return services;
        }
    }

    public class CertificateServiceOptions
    {
        public string Path { get; set; }
        public string Password { get; set; }
    }
}
