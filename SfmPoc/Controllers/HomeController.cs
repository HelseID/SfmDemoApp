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
        // This is the front end application. 

        private readonly ILogger<HomeController> _logger;
        private readonly IMemoryCache _memoryCache;

        public HomeController(ILogger<HomeController> logger, IMemoryCache memoryCache)
        {
            _logger = logger;
            _memoryCache = memoryCache;
        }

        public IActionResult Index()
        {
            // This page is open for anonymous access
            // If the user is logged on we will display information about the user 
            // The access token is displayed here, but it would normally not be exposed to the browser

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
            // This page is only available if the visitor has the right cookie set and that cookie points to a valid user session
            // Here we use the access token in the back end to call an external api and returns the result to the browser.
            // We print out the access token, but we should not do taht in a real application

            // Retrieves the access token for the current user session
            // If there is no user session we could choose to fail or maybe tell the user they must log on
            var accessToken = GetCurrentAccessToken();
            ViewBag.AccessToken = accessToken;

            // Calls the external api using the access token
            var apiResult = await CallExternalApi(accessToken);

            return View("Secured", apiResult);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private async Task<string> CallExternalApi(string accessToken)
        {
            // Calls an external api using the access token as a bearer token to gain access

            var client = new HttpClient();
            client.SetBearerToken(accessToken);

            // Just a fancy way of determining the url of the api... 
            // The api is not really external in this case, but you get the point!
            var apiUrl = $"{Request.Scheme}://{Request.Host.ToUriComponent()}/api/sample";

            var result = await client.PostAsync(apiUrl, new StringContent(""));
            var apiResult = await result.Content.ReadAsStringAsync();

            return apiResult;
        }

        private string GetAccessTokenForSession(string sessionId)
        {
            // Gets the access token that belongs to the given session
            var accessToken = _memoryCache.Get<string>(sessionId + "_at");
            return accessToken;
        }

        private string GetCurrentAccessToken()
        {
            // Gets the session id from the cookie via the claims principal
            // Then gets the access token for that session id

            var sessionId = User.FindFirstValue("SessionId");
            if (string.IsNullOrEmpty(sessionId))
            {
                return "";
            }

            return GetAccessTokenForSession(sessionId);
        }
    }
}
