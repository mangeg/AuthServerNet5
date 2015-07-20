namespace AuthServerNet5Identity.Identity
{
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.EntityFramework;

    public class ApplicationUserStore : UserStore<ApplicationUser, ApplicationRole, UserContext, int>
    {
        public ApplicationUserStore( UserContext context, IdentityErrorDescriber describer = null )
            : base( context, describer ) {}
    }
}