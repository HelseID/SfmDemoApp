using Microsoft.AspNetCore.Mvc;

namespace SfmPoc.Controllers
{
    [Route("api/sample")]
    [ApiController]
    public class SampleApiController : ControllerBase
    {
        [HttpPost]
        public string Post()
        {
            // This is just a very simple api that returns a string
            // We handle the token manually so we don't have to setup a much more complex web application
            // that handles many types of authentication

            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            if (TokenValidator.ValidateAccessToken(token, out _))
            {
                return "API called OK";
            }
            else
            {
                return "API failed";
            }
        }
    }
}
