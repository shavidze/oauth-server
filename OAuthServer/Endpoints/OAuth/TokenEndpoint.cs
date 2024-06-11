using System.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OAuthServer.Endpoints.OAuth
{
    public class TokenEndpoint
    {
        public static async Task<IResult> Handle(HttpRequest request, DevKeys devKeys)
        {
            string grantType = "", code = "", redirectUri = "", codeVerifier = "";

            try
            {
                // Read the request body asynchronously
                var body = await new StreamReader(request.Body).ReadToEndAsync();
                // Parse the query string
                var parsedBody = HttpUtility.ParseQueryString(body);

                // Extract parameters
                grantType = parsedBody["grant_type"] ?? string.Empty;
                code = parsedBody["code"] ?? string.Empty;
                redirectUri = parsedBody["redirect_uri"] ?? string.Empty;
                codeVerifier = parsedBody["code_verifier"] ?? string.Empty;
            }
            catch (Exception ex)
            {
                // Handle exceptions (e.g., log the error)
                return Results.BadRequest(new { error = "Invalid request format", details = ex.Message });
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
                })
            });
        }
    }
}