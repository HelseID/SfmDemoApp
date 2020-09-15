using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using SfmPoc.Models;

namespace SfmPoc.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IMemoryCache _memoryCache;

        public HomeController(ILogger<HomeController> logger, IMemoryCache memoryCache)
        {
            _logger = logger;
            _memoryCache = memoryCache;
        }

        public IActionResult Index()
        {
            ViewBag.AccessToken = GetCurrentAccessToken();
            return View(User.Claims.ToList());
        }

        public IActionResult AccessDenied()
        {
            return Content("Access denied!");
        }

        [Authorize(policy: "HasSession")]
        public async Task<IActionResult> Secured()
        {
            var accessToken = GetCurrentAccessToken();
            ViewBag.AccessToken = accessToken;

            var client = new HttpClient();
            client.SetBearerToken(accessToken);

            var apiUrl = $"{Request.Scheme}://{Request.Host.ToUriComponent()}/api/sample";

            var result = await client.PostAsync(apiUrl, new StringContent(""));
            var apiResult = await result.Content.ReadAsStringAsync();

            return View("Secured", apiResult);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private string GetAccessTokenForSession(string sessionId)
        {
            var accessToken = _memoryCache.Get<string>(sessionId + "_at");
            return accessToken;
        }

        private string GetCurrentAccessToken()
        {
            var sessionId = User.FindFirstValue("SessionId");
            if (string.IsNullOrEmpty(sessionId))
            {
                return "";
            }

            return GetAccessTokenForSession(sessionId);
        }
    }
}
