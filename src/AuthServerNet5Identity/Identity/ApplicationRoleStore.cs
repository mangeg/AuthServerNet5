namespace AuthServerNet5Identity.Identity
{
    using Microsoft.AspNet.Identity.EntityFramework;

    public class ApplicationRoleStore : RoleStore<ApplicationRole, UserContext, int>
    {
        public ApplicationRoleStore( UserContext context )
            : base( context ) {}
    }
}