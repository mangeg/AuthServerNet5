namespace AuthServerNet5Identity.Identity
{
    using Microsoft.AspNet.Identity.EntityFramework;

    public class ApplicationUser : IdentityUser<int>
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
