using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;

namespace SfmPoc.Controllers
{
    [ApiController]
    public class SessionController : ControllerBase
    {
        private readonly IMemoryCache memoryCache;

        public SessionController(IMemoryCache memoryCache)
        {
            this.memoryCache = memoryCache;
        }

        [HttpPost]
        [Route("api/createsession")]
        public SessionIdModel Post(InitializeModel model)
        {
            if(model == null || string.IsNullOrEmpty(model.AccessToken ))
            {
                throw new InvalidOperationException();
            }

            if(!TokenValidator.ValidateAccessToken(model.AccessToken))
            {
                throw new Exception("Access token was not validated");
            }

            var oneTimeCodeBytes = new byte[64];
            var sessionIdBytes = new byte[64];

            var cryptoServiceProvider = new RNGCryptoServiceProvider();
            cryptoServiceProvider.GetBytes(oneTimeCodeBytes);
            cryptoServiceProvider.GetBytes(sessionIdBytes);

            var sessionId = Convert.ToBase64String(sessionIdBytes);
            var oneTimeCode = Convert.ToBase64String(oneTimeCodeBytes);

            memoryCache.Set(sessionId + "_at", model.AccessToken);
            memoryCache.Set(sessionId + "_hash", model.NonceHash);
            memoryCache.Set(oneTimeCode, sessionId);

            return new SessionIdModel { OneTimeCode = oneTimeCode, SessionId = sessionId };
        }

        [HttpPost]
        [Route("api/refreshSession")]
        public IActionResult Update(UpdateModel model)
        {
            if (model == null || string.IsNullOrEmpty(model.AccessToken))
            {
                throw new InvalidOperationException();
            }

            if (!TokenValidator.ValidateAccessToken(model.AccessToken))
            {
                throw new Exception("Access token was not validated");
            }

            memoryCache.Set(model.SessionId + "_at", model.AccessToken);

            return Ok();
        }
    }

    public class InitializeModel
    {
        public string AccessToken { get; set; }
        public string NonceHash { get; set; }
    }

    public class SessionIdModel
    {
        public string SessionId { get; set; }
        public string OneTimeCode { get; set; }
    }

    public class UpdateModel
    {
        public string AccessToken { get; set; }
        public string SessionId { get; set; }
    }
}
