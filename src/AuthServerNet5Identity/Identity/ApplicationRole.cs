namespace AuthServerNet5Identity.Identity
{
    using Microsoft.AspNet.Identity.EntityFramework;

    public class ApplicationRole : IdentityRole<int>
    {
        public string Description { get; set; }
    }
}