namespace AuthServerNet5Identity.Identity
{
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Identity;

    /*public class MyClaimsIdentityFactory : ClaimsIdentityFactory<MyUser>
    {
        public MyClaimsIdentityFactory()
        {
            UserIdClaimType = Thinktecture.IdentityServer.Core.Constants.ClaimTypes.Subject;
            UserNameClaimType = Thinktecture.IdentityServer.Core.Constants.ClaimTypes.PreferredUserName;
            RoleClaimType = Thinktecture.IdentityServer.Core.Constants.ClaimTypes.Role;
        }

        public override async Task<ClaimsIdentity> CreateAsync( UserManager<MyUser, int> manager, MyUser user, string authenticationType )
        {
            var ci = await base.CreateAsync( manager, user, authenticationType );
            if ( !string.IsNullOrWhiteSpace( user.FirstName ) )
            {
                ci.AddClaim( new Claim( "given_name", user.FirstName ) );
            }
            if ( !string.IsNullOrWhiteSpace( user.FirstName ) )
            {
                ci.AddClaim( new Claim( "last_name", user.LastName ) );
            }
            return ci;
        }
    }*/
}
