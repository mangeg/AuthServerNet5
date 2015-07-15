namespace MvcClient.Controllers
{
    using System.Security.Claims;
    using Microsoft.AspNet.Authorization;
    using Microsoft.AspNet.Mvc;

    public class HomeController : Controller
    {
        [Authorize]
        public IActionResult Index()
        {
            var claims = User.Claims;
            
            return View( claims );
        }
    }
}