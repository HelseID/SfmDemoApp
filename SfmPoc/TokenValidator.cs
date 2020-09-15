using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace SfmPoc
{
    static class TokenValidator
    {
        const string signingKey = "MIIFBzCCA++gAwIBAgILAc2fG6Tv6ws1fwUwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCTk8xHTAbBgNVBAoMFEJ1eXBhc3MgQVMtOTgzMTYzMzI3MSMwIQYDVQQDDBpCdXlwYXNzIENsYXNzIDMgVGVzdDQgQ0EgMzAeFw0xODA5MTEwNTIwNTRaFw0yMTA5MTAyMTU5MDBaMG0xCzAJBgNVBAYTAk5PMRswGQYDVQQKDBJOT1JTSyBIRUxTRU5FVFQgU0YxEDAOBgNVBAsMB0hlbHNlSUQxGzAZBgNVBAMMEk5PUlNLIEhFTFNFTkVUVCBTRjESMBAGA1UEBRMJOTk0NTk4NzU5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Imh5XgI8But2O64eRIdb5cTZmE6BWoL/p4rMwLgEAh0VlXgDqTx+xuy6HGsNtPZbxl6gHBNimr0Wyx6xCDXUPafPhPqE91PeCmVgLBAqDU4c56PQyFkBHIHJMAP2D3sDUEzc9gODK0mFbznUjxuU6X8FEmP/ioFM/5fKrSpVG+KAfzv5/TBy37zRyldAVHkFHiR3EdtOCivIEqcC4PhKHesUug1wmawSEUI6Z1ViuLeuNnn/b0T7Ng23tVcAM8mrdHn/ES06YuaXZYmnUN0GEiK/J1ewpvBb/EMHGO4ocbodjuPdjO3SwP/hXTE2MsjN8xS7vmpqeoV9KUDHQFKCwIDAQABo4IBwjCCAb4wCQYDVR0TBAIwADAfBgNVHSMEGDAWgBQ/rvV4C5KjcCA1X1r69ySgUgHwQTAdBgNVHQ4EFgQUd2lMsttTomQN4RWhBaPHMFTd0SkwDgYDVR0PAQH/BAQDAgZAMBYGA1UdIAQPMA0wCwYJYIRCARoBAAMCMIG7BgNVHR8EgbMwgbAwN6A1oDOGMWh0dHA6Ly9jcmwudGVzdDQuYnV5cGFzcy5uby9jcmwvQlBDbGFzczNUNENBMy5jcmwwdaBzoHGGb2xkYXA6Ly9sZGFwLnRlc3Q0LmJ1eXBhc3Mubm8vZGM9QnV5cGFzcyxkYz1OTyxDTj1CdXlwYXNzJTIwQ2xhc3MlMjAzJTIwVGVzdDQlMjBDQSUyMDM/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdDCBigYIKwYBBQUHAQEEfjB8MDsGCCsGAQUFBzABhi9odHRwOi8vb2NzcC50ZXN0NC5idXlwYXNzLm5vL29jc3AvQlBDbGFzczNUNENBMzA9BggrBgEFBQcwAoYxaHR0cDovL2NydC50ZXN0NC5idXlwYXNzLm5vL2NydC9CUENsYXNzM1Q0Q0EzLmNlcjANBgkqhkiG9w0BAQsFAAOCAQEALKawhumnN8vCF+cmcLDZEpkfubOHqPfp7jBGcTSjFMGSbtrHxHWnzkJcsn9kTAEPIpqtThNQmAEM2WvmdEQrFVSdrf+eQpA+cOBhQBpSrJzTOI9KSERS/DxwuImSHj/6P6joSeQQVNAKo4U9o9xu+qQGvIxAl5bOEMaDY89beyvfJpaJO+NXKjy6xl8RpbdRO3bO62flyrg3h87ebHxZpQZrlJpwkEnK0AcKSQ4fhIiZqKSHMmGvxRp3WAoU/8ePa0u/+GacifncBRka7PdeG2CuW6KyPTf54ZiTVXhJ9TnxUU5F2Fg4mpA0466u3uhEh9KeEX6pvJgNOGSHh2x/cw==";
        static readonly SecurityKey securityKey = new X509SecurityKey(new System.Security.Cryptography.X509Certificates.X509Certificate2(Convert.FromBase64String(signingKey)));


        public static bool ValidateAccessToken(string accessToken, out ClaimsPrincipal validatedPrincipal)
        {   
            var parameters = new TokenValidationParameters
            {
                ValidAudience = "e-helse/SFM.api",
                IssuerSigningKey = securityKey,
                ValidIssuer = "https://helseid-sts.test.nhn.no",
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true
            };

            try
            {
                validatedPrincipal = new JwtSecurityTokenHandler().ValidateToken(accessToken, parameters, out SecurityToken validatedToken);
            }
            catch (Exception ex)
            {
                // TODO: Handle the exception?
                validatedPrincipal = null;
                return false;
            }

            return true;
        }

    }
}
