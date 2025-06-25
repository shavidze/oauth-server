using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OAuthServer.Endpoints.OAuth
{
    public static class TokenEndpoint
    {
        public static async Task<IResult> Handle(HttpRequest request, DevKeys devKeys, IDataProtectionProvider dataProtectionProvider)
        {
            string grantType = "", code = "", redirectUri = "", codeVerifier = "";
            try
            {
                var bodyBytes = await request.BodyReader.ReadAsync();
                var bodyContent = Encoding.UTF8.GetString(bodyBytes.Buffer);
                
                Console.WriteLine(bodyContent);
                
                foreach (var part in bodyContent.Split('&'))
                {
                    var subParts = part.Split('=');
                    var key = subParts[0];
                    var value = subParts[1];

                    switch (key)
                    {
                        case "grant_type":
                            grantType = value;
                            break;
                        case "code":
                            code = value;
                            break;
                        case "redirect_uri":
                            redirectUri = value;
                            break;
                        case "code_verifier":
                            codeVerifier = value;
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle exceptions (e.g., log the error)
                return Results.BadRequest(new { error = "Invalid request format", details = ex.Message });
            }
            
            /*
             * ამოვიღოთ კოდში მოსული მნიშვნელობები, `clientId`,`clientSecret`,`CodeChallengeMethod`,`RedirectUri`,`Expiry`.
             */
            var protector = dataProtectionProvider.CreateProtector("oauth");
        
            // გავხსნათ ჩვენი კოდი.
            var codeString = protector.Unprotect(code);

            // დესერიალიზაცია გავუკეთოთ `AuthCode`-ში.
            var authCode = JsonSerializer.Deserialize<AuthCode>(codeString);

            // შევამოწმოთ, ხო იგივე კლიენტი გვესაუბრება ვინც დაიწყო `flow`
            if (authCode == null || !ValidateCodeVerifier(authCode, codeVerifier))
            {
                return Results.BadRequest();
            }
            
            // შევქმნათ ჯსონ ვებ ტოკენი, რომელშიც გავწერთ ქლეიმებს, რამდენი ხანია ვალიდური, da
            // sign in credentials
            var handler = new JsonWebTokenHandler();

            return Results.Ok(new
            {
                // შევქმნათ ტოკენი, მერე აღვწეროთ დესქრიპტორით, ქლეიმები, და სხვა პარამეტრები
                // ბოლო პარამეტრი არის `SignInCredentials` სადაც ვატანთ, `RsaSecurityKey(რომლის private key იყენებს)` და ალგორითმს
                // პირველ რიგში ტოკენის კონტენტი დაიჰეშება მეორე პარამეტრით - `SecurityAlgorithms.RsaSha256`
                // შემდეგ, მისთვის შეიქმნება კრიპტოგრაფიული მნიშვნელობა - private key-თ.
                // როდესაც მოვა ტოკენი, ამ ხელმოწერით, ჯერ `public key`-ით დავაბრუნებ დაჰეშილ მნიშვნელობას,
                // შემდეგ ტოკენის ორიგინალ კონტენტს, იგივე ჰეშ ალგორითმით დავჰეშავ და შევადარებ თუ ტოლია, ესეიგი ჩემია.
                
                access_token = handler.CreateToken(new SecurityTokenDescriptor()
                {
                    Claims = new Dictionary<string, object>()
                    {
                        [JwtRegisteredClaimNames.Sub] = Guid.NewGuid().ToString(),
                        ["custom"] = "foo"
                    },
                    Expires = DateTime.Now.AddMinutes(15),
                    TokenType = "Bearer",
                    SigningCredentials = new SigningCredentials(devKeys.RsaSecurityKey, SecurityAlgorithms.RsaSha256)
                }),
                token_type = "Bearer"
            });
        }

        /**
         *   code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
         *   კოდ ჩელენჯს ასე აგენერირებს კლიენტი,ახლა იგივე გავიმეროროთ და შევადაროთ.
         */
        private static bool ValidateCodeVerifier(AuthCode code, string codeVerifier)
        {
            using var sha256 = SHA256.Create();
            var codeChallenge = Base64UrlEncoder.Encode(sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier)));
            return code.CodeChallenge == codeChallenge;
        }
    }
}