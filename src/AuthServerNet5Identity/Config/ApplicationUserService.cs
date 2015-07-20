namespace AuthServerNet5Identity.Config
{
    using Identity;
    using Microsoft.AspNet.Identity;
    using Utils;

    public class ApplicationUserService : UserService<ApplicationUser, int>
    {
        public ApplicationUserService( UserManager<ApplicationUser> userManager )
            : base( userManager )
        {
        }
    }
}