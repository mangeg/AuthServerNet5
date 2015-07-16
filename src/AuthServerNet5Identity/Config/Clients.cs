namespace AuthServerNet5Identity.Config
{
    using System.Collections.Generic;
    using Thinktecture.IdentityServer.Core.Models;

    public class Clients
    {
        public static List<Client> Get()
        {
            return new List<Client> {
                new Client {
                    ClientName = "Implicit MVC6 Client",
                    Enabled = true,
                    ClientId = "mvc6Implicit",
                    ClientSecrets = new List<ClientSecret> {
                        new ClientSecret( "secret".Sha256() )
                    },
                    Flow = Flows.Implicit,
                    RequireConsent = true,
                    AllowRememberConsent = false,
                    RedirectUris = new List<string> {
                        "http://localhost:14567/"
                    }
                },
                new Client {
                    ClientName = "Hybrid MVC6 Client",
                    Enabled = true,
                    ClientId = "mvc6Hybrid",
                    Flow = Flows.Hybrid,
                    RequireConsent = true,
                    AllowRememberConsent = false,
                    RedirectUris = new List<string> {
                        "http://localhost:14567/"
                    }
                }
            };
        }
    }
}
