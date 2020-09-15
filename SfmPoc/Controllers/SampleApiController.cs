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
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

            if (TokenValidator.ValidateAccessToken(token))
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
