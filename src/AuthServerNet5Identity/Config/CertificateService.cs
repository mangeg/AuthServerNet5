namespace AuthServerNet5Identity.Config
{
    using System.IO;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Framework.Configuration;

    public class CertificateService
    {
        private readonly IConfiguration _config;
        public CertificateService(IConfiguration config)
        {
            _config = config;
        }

        public X509Certificate2 Get()
        {
            var path = _config.Get( "SignatureCert:Path" );
            var password = _config.Get( "SignatureCert:Password" );

            return new X509Certificate2( path, password );
        }
    }
}