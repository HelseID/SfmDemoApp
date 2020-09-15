using IdentityModel.Client;
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Text;
using System.Security.Cryptography;
using System.Web;

namespace SfmEpj
{
    class Program
    {
        static async Task Main(string[] args)
        {

            var accessToken = await GetAccessTokenFromHelseID();

            (var nonceBase64, var nonceHash) = GetNonce();

            var content = new StringContent(JsonConvert.SerializeObject(new { accessToken, nonceHash }), Encoding.UTF8, "application/json");
            var response = await new HttpClient().PostAsync("https://localhost:44379/api/createsession/", content);

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception("Logon failed: " + response.ReasonPhrase);
            }

            var session = JsonConvert.DeserializeObject<SessionIdModel>(await response.Content.ReadAsStringAsync());

            var oneTimeCode = HttpUtility.UrlEncode(session.OneTimeCode);
            var nonce = HttpUtility.UrlEncode(nonceBase64);
            var url = $"https://localhost:44379/Home/Login?oneTimeCode={oneTimeCode}&nonce={nonce}";

            Console.WriteLine("Logging on to SFM");
            Console.WriteLine("Url: " + url);
            Process.Start(new ProcessStartInfo("cmd", $"/c start {url.Replace("&", "^&")}") { CreateNoWindow = true });


            Console.WriteLine();
            Console.WriteLine("Press enter to update access token");
            Console.ReadLine();

            var newAccessToken = await GetAccessTokenFromHelseID();

            var updateContent = new StringContent(JsonConvert.SerializeObject(new { accessToken = newAccessToken, session.SessionId }), Encoding.UTF8, "application/json");
            var updateResponse = await new HttpClient().PostAsync("https://localhost:44379/api/refreshSession/", updateContent);

            if (!updateResponse.IsSuccessStatusCode)
            {
                throw new Exception("Update token failed: " + updateResponse.ReasonPhrase);
            }

            Console.WriteLine("Access token was updated");
        }

        private static (string nonceBase64, string nonceHash) GetNonce()
        {
            var nonce = new byte[64];
            new RNGCryptoServiceProvider().GetBytes(nonce);
            var nonceBase64 = Convert.ToBase64String(nonce);
            var hashAlg = SHA256.Create();
            var nonceHash = Convert.ToBase64String(hashAlg.ComputeHash(nonce));
            return (nonceBase64, nonceHash);
        }

        static async Task<string> GetAccessTokenFromHelseID()
        {
            var request = new ClientCredentialsTokenRequest
            {
                ClientId = "ac72c422-13b1-4a56-8912-9b1b4ff24269",
                ClientSecret = "3JVs6zu4UUHPPpwfm4L8NvdW8TXypKA24pms9KM5_rWup-qTE9bMiPzZzTukfBiy",
                Address = "https://helseid-sts.test.nhn.no/connect/token",
                Scope = "e-helse/sfm.api/sfm.api"
            };

            var token = await new HttpClient().RequestClientCredentialsTokenAsync(request);

            if (token.IsError)
            {
                throw new Exception("Did not get an access token: " + token.Error);
            }

            return token.AccessToken;
        }
    }

    public class SessionIdModel
    {
        public string SessionId { get; set; }
        public string OneTimeCode { get; set; }
    }
}
