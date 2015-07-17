namespace AuthServerNet5Identity.Config
{
    using System.IO;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Framework.Configuration;
    using Microsoft.Framework.Logging;
    using Microsoft.Framework.Runtime;

    public class CertificateService : ICertificateService
    {
        private readonly IConfiguration _config;
        private readonly IApplicationEnvironment _appEnv;
        private readonly ILogger _logger;
        public CertificateService( IConfiguration config, ILoggerFactory loggerFactory, IApplicationEnvironment appEnv )
        {
            _config = config;
            _appEnv = appEnv;
            _logger = loggerFactory.CreateLogger<CertificateService>();
        }

        public X509Certificate2 Get()
        {
            var path = _config.Get( "SignatureCert:Path" );
            var password = _config.Get( "SignatureCert:Password" );

            var fullPath = Path.Combine( _appEnv.ApplicationBasePath, path );

            _logger.LogInformation( $"Certificate Path: {fullPath}" );
            _logger.LogInformation( $"Certificate Password: {password}" );

            return new X509Certificate2( fullPath, password );
        }
    }
}
