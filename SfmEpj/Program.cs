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
        static async Task Main()
        {
            // This application simulates an EPJ that wants to start SFM.
            // The application will get an access token from HelseID that is passes on to SFM
            // using a backend-call. SFM replies with a Session ID that indicates the users session
            // and a One Time Code that is used to authenticate the user via the web browser.


            // Gets an access token from HelseID
            // This application uses a simple setup and not the full SFM client setup
            var accessToken = await GetAccessTokenFromHelseID();

            // Calculates a nonce (number used once, a one-time secret)
            // These are used by SFM to prove that the front-end and back-end calls are from the
            // same origin
            (var nonceBase64, var nonceHash) = GetNonce();

            // Establishes a session against the SFM backend by passing 
            // the access token and a hash of the nonce
            var content = new StringContent(JsonConvert.SerializeObject(new { accessToken, nonceHash }), Encoding.UTF8, "application/json");
            var response = await new HttpClient().PostAsync("https://localhost:44379/api/createsession/", content);

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception("Logon failed: " + response.ReasonPhrase);
            }

            // Parses the response and gets the Session ID and the one-time-code that is used for logon
            var session = JsonConvert.DeserializeObject<SessionIdModel>(await response.Content.ReadAsStringAsync());

            var oneTimeCode = HttpUtility.UrlEncode(session.OneTimeCode);
            var nonce = HttpUtility.UrlEncode(nonceBase64);
            var url = $"https://localhost:44379/login?oneTimeCode={oneTimeCode}&nonce={nonce}";

            // Open the system browser and logon to the application
            // In a real EPJ this would either be an embedded browser or a new browser tab
            Console.WriteLine("Logging on to SFM");
            Console.WriteLine("Url: " + url);
            Process.Start(new ProcessStartInfo("cmd", $"/c start {url.Replace("&", "^&")}") { CreateNoWindow = true });


            Console.WriteLine();
            Console.WriteLine("Press enter to update access token");
            Console.ReadLine();

            // Now the access token is about to expire and the EPJ must update it
            // Gets a new token from HelseID
            // In a real application this would probably be done using a refresh token
            var newAccessToken = await GetAccessTokenFromHelseID();

            // Calls the refresh session endpoint
            var updateContent = new StringContent(JsonConvert.SerializeObject(new { accessToken = newAccessToken, session.SessionId }), Encoding.UTF8, "application/json");
            var updateResponse = await new HttpClient().PostAsync("https://localhost:44379/api/refreshSession/", updateContent);

            if (!updateResponse.IsSuccessStatusCode)
            {
                throw new Exception("Update token failed: " + updateResponse.ReasonPhrase);
            }

            Console.WriteLine("Access token was updated");
        }


        private static (string nonceBase64, string nonceHashBase64) GetNonce()
        {
            // Generates a random number (nonce) 
            // We return two versions of this number: 
            // - The hashed version is used in the first call where we create the session. 
            //   The server stores this value for later verification.
            // - The full version is passed by the browser when logging on.
            //   The server calculates the hash of this and uses that as a proof that the front-end and
            //   back end calls are from the same application.
            var nonce = new byte[64];
            new RNGCryptoServiceProvider().GetBytes(nonce);
            var nonceBase64 = Convert.ToBase64String(nonce);
            var hashAlg = SHA512.Create();
            var nonceHashBase64 = Convert.ToBase64String(hashAlg.ComputeHash(nonce));
            return (nonceBase64, nonceHashBase64);
        }

        static async Task<string> GetAccessTokenFromHelseID()
        {
            // Hardcoded client setup against HelseID
            // DO NOT DO THIS IN A REAL APPLICATION! :-)
            // To keep things simple we do a client credentials (machine-to-machine) flow here
            // In a real application you would probably get the access token using other mechanisms
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
