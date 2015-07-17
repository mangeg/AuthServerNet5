namespace AuthServerNet5Identity.Config
{
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Framework.Configuration;
    using Microsoft.Framework.Logging;

    public class CertificateService
    {
        private readonly IConfiguration _config;
        private ILogger _logger;
        public CertificateService( IConfiguration config, ILoggerFactory loggerFactory )
        {
            _config = config;
            _logger = loggerFactory.CreateLogger<CertificateService>();
        }

        public X509Certificate2 Get()
        {
            var path = _config.Get( "SignatureCert:Path" );
            var password = _config.Get( "SignatureCert:Password" );

            _logger.LogInformation( $"Path: {path}" );
            _logger.LogInformation( $"Password: {password}" );

            return new X509Certificate2( path, password );
        }
    }
}
