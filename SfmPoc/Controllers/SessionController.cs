using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using SfmPoc.Models;

namespace SfmPoc.Controllers
{
    [ApiController]
    public class SessionController : ControllerBase
    {
        // Handles the protocol for setting up a user session, refreshing a user session with a new
        // access token and for performing the logon using a One Time Code and the nonce. 


        // For this sample we are using a memory cache as our storage mechanism due to simplicity
        private readonly IMemoryCache _memoryCache;

        public SessionController(IMemoryCache memoryCache)
        {
            _memoryCache = memoryCache;
        }

        [HttpPost]
        [Route("api/createsession")]
        public SessionIdModel CreateSession(InitializeModel model)
        {
            // Creates a new user session and returns the Session ID and One Time Code 
            // used to logon

            if(model == null || string.IsNullOrEmpty(model.AccessToken ))
            {
                throw new InvalidOperationException();
            }

            // Makes sure the access token is valid and meant for us
            if (!TokenValidator.ValidateAccessToken(model.AccessToken, out _))
            {
                throw new Exception("Access token was not validated");
            }

            // Generates a unique session id and a unique one time code
            var sessionId = GenerateRandomValue();
            var oneTimeCode = GenerateRandomValue();

            // Stores the access token, the hashed nonce and the one time code used for the session
            _memoryCache.Set(sessionId + "_at", model.AccessToken);
            _memoryCache.Set(sessionId + "_hash", model.NonceHash);
            _memoryCache.Set(oneTimeCode, sessionId);

            return new SessionIdModel { OneTimeCode = oneTimeCode, SessionId = sessionId };
        }

        [HttpPost]
        [Route("api/refreshSession")]
        public IActionResult RefreshSession(UpdateModel model)
        {
            // Updates an existing session with a new access token
            // The access token is validated and the session id is validated
            // Finally we ensure that the access token belongs to this session

            if (model == null || string.IsNullOrEmpty(model.AccessToken))
            {
                throw new InvalidOperationException();
            }

            // Validates the new access token, keeps the claims for later validation
            if (!TokenValidator.ValidateAccessToken(model.AccessToken, out ClaimsPrincipal newPrincipal))
            {
                throw new Exception("Access token was not validated");
            }

            // Ensures that we have an existing session by fetching the access token for that session id
            // In a real application you will probably have different mechanisms for session validation... :-)
            var originalAccessToken = _memoryCache.Get<string>(model.SessionId + "_at");

            // Extracts the claims from the original access token
            TokenValidator.ValidateAccessToken(originalAccessToken, out ClaimsPrincipal originalPrincipal);

            // Validates that the new access token is a valid replacement of the current access token
            // Since we are using a simplified model here, we only have the client id to use for validation.
            // In a real application you would also check the user PID, possibly the SFM_ID claim when it is ready
            // and possibly other claims as well
            if(newPrincipal.FindFirstValue("client_id") != originalPrincipal.FindFirstValue("client_id"))
            {
                throw new Exception("Client ID of original and new access token does not match!");
            }

            // Replaces the current access token with the new one for the given session
            _memoryCache.Set(model.SessionId + "_at", model.AccessToken);

            return Ok();
        }

        [Route("/login")]
        public IActionResult Login(string oneTimeCode, string nonce)
        {
            // Handles logon by validating the one time code and then validating the nonce
            // If both are ok we setup a session cookie that contains the corresponding session id.
            // This session id can be used to retrieve the access token that is stored in our backend

            // Validates the one time code and retrieves the corresponding one time code
            var sessionId = GetSessionId(oneTimeCode);
            if (string.IsNullOrEmpty(sessionId))
            {
                throw new Exception("Unknown one time code " + oneTimeCode);
            }

            // Validates that the hash of the nonce is equal to the hash we retrieved earlier
            ValidateSecret(sessionId, nonce);

            // Sets up a cookie that handles the user sesssion
            SignInUserToSession(sessionId);

            // Redirects the user back to the main page of our application
            return RedirectToAction("Index", "Home");
        }

        private void SignInUserToSession(string sessionId)
        {
            // Builds a claims principal that contains the session id
            // In a real application this principal would probably also contain 
            // information about the logged on user 
            var claims = new List<Claim>
            {
                new Claim("SessionId", sessionId)
            };
            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var user = new ClaimsPrincipal(identity);

            // Sets up the cookie
            HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, user);
        }

        private string GenerateRandomValue()
        {
            // Uses the RNGCryptoServiceProvider to create cryptographically secure random values

            // 64 bytes is an arbitrary value. The value should be long enough that guessing it would be very unlikely
            var randomValue = new byte[64]; 

            var cryptoServiceProvider = new RNGCryptoServiceProvider();
            cryptoServiceProvider.GetBytes(randomValue);

            return Convert.ToBase64String(randomValue);
        }

        private string GetSessionId(string oneTimeCode)
        {
            // Returns the corresponding session id for the one time code
            // The one time code is then invalidated 

            var sessionId = _memoryCache.Get<string>(oneTimeCode);
            _memoryCache.Remove(oneTimeCode);
            return sessionId;
        }

        private void ValidateSecret(string sessionId, string nonce)
        {
            // Calculates the hash of the nonce and compares it to the hash stored for the current session
            // Even if the comparison fails, the hash is deleted. This way we guarantee that brute force attacks are impossible

            // Sets up the hash algorithm. Which one you want to use is up to your project, but since the calculation 
            // is done only once per user logon we can safely use a powerful algorithm here.
            using var hashAlg = SHA512.Create();

            var computedHash = Convert.ToBase64String(hashAlg.ComputeHash(Convert.FromBase64String(nonce)));

            // Retrieves the stored hash for the current session id
            var inputHash = _memoryCache.Get<string>(sessionId + "_hash");
            _memoryCache.Remove(sessionId + "_hash");

            // Fail if the hashes are not the same
            if (inputHash != computedHash)
            {
                throw new Exception("Invalid secret! Got secret with hash: " + computedHash + ". Expected hash: " + inputHash + ".");
            }
        }
    }

}
