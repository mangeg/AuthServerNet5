namespace AuthServerNet5Identity.Config
{
    using System.Security.Cryptography.X509Certificates;

    public interface ICertificateService
    {
        X509Certificate2 Get();
    }
}
