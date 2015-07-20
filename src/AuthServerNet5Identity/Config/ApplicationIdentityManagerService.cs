namespace AuthServerNet5Identity.Config
{
    using Identity;
    using Microsoft.AspNet.Identity;
    using Microsoft.Framework.OptionsModel;

    public class ApplicationIdentityManagerService : AspNetIdentityManagerService<ApplicationUser, int, ApplicationRole, int>
    {
        public ApplicationIdentityManagerService( UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, IOptions<IdentityOptions> userOptions, bool includeAccountProperties = true )
            : base( userManager, roleManager, userOptions, includeAccountProperties )
        {
        }
    }
}