namespace MvcClient.Controllers
{
    using System.Security.Claims;
    using Microsoft.AspNet.Authorization;
    using Microsoft.AspNet.Mvc;

    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Claims()
        {
            var claims = User.Claims;

            return View( claims );
        }
    }
}