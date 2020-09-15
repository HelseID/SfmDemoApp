using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace SfmPoc.Controllers
{
    [Route("api/sample")]
    [ApiController]
    public class SampleApiController : ControllerBase
    {
        [HttpPost]
        public string Post()
        {
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
