namespace AuthServerNet5Identity.Identity
{
    using Microsoft.AspNet.Identity.EntityFramework;
    using Microsoft.Data.Entity;

    public sealed class UserContext : IdentityDbContext<ApplicationUser, ApplicationRole, int>
    {
        public UserContext()
        {
            //Database.EnsureCreated();
        }

        protected override void OnModelCreating( ModelBuilder builder )
        {
            base.OnModelCreating( builder );
        }
    }
}