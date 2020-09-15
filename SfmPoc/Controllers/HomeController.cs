using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
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

        public IActionResult Login(string oneTimeCode, string nonce)
        {
            var sessionId = GetSessionId(oneTimeCode);

            if (string.IsNullOrEmpty(sessionId))
            {
                throw new Exception("Unknown one time code " + oneTimeCode);
            }

            ValidateSecret(sessionId, nonce);

            var claims = new List<Claim>
            {
                new Claim("SessionId", sessionId)
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var user = new ClaimsPrincipal(identity);
            HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, user);

            return RedirectToAction("Index");
        }

        private string GetSessionId(string oneTimeCode)
        {
            var sessionId = _memoryCache.Get<string>(oneTimeCode);
            _memoryCache.Remove(oneTimeCode);
            return sessionId;
        }

        private void ValidateSecret(string sessionId, string nonce)
        {
            using var hashAlg = SHA256.Create();

            var computedHash = Convert.ToBase64String(hashAlg.ComputeHash(Convert.FromBase64String(nonce)));
            var inputHash = _memoryCache.Get<string>(sessionId + "_hash");
            _memoryCache.Remove(sessionId + "_hash");

            if (inputHash != computedHash)
            {
                throw new Exception("Invalid secret! Got secret with hash: " + computedHash + ". Expected hash: " + inputHash + ".");
            }
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
