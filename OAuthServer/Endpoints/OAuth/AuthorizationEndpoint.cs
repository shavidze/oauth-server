using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.DataProtection;

namespace OAuthServer.Endpoints.OAuth;

public static class AuthorizationEndpoint
{
    public static IResult Handle(HttpRequest request,IDataProtectionProvider dataProtectionProvider)
    {
        var iss = HttpUtility.UrlEncode("https://localhost:5001");
        
        // state არის უნიკალური მნიშვნელობა, რომელიც თავიდან იქმნება კლიენტის მხრიდან,რომ
        // სერვერიდან მოსული ინფორმაცია, დაადასტუროს რომ ნამდვილად იმ სერვერიცსაა რომელსაც ელეპარაკება
        // ავტორიზაციის სერვერი, ბოლოს ამ მნიშნველობასაც უბრუნებს ქოლ ბექის ქუერი პარამეტრში უზერ აგენტს, და აგენტი კლიენტს.
        request.Query.TryGetValue("state", out var state);
        
        if (!request.Query.TryGetValue("response_type", out var responseType))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                state,
                iss
            });    
        }
        
        request.Query.TryGetValue("client_id", out var clinetId);
        request.Query.TryGetValue("client_secret", out var clientSecret);
        request.Query.TryGetValue("code_challenge", out var codeChallenge);
        request.Query.TryGetValue("code_challenge_method", out var codeChallengeMethod);
        request.Query.TryGetValue("redirect_uri", out var redirectUri);
        request.Query.TryGetValue("scope", out var scope);

        

        /*
         * დავაგენერიროთ კოდი
         */
        var protector = dataProtectionProvider.CreateProtector("oauth");
        var code = new AuthCode()
        {
            ClientId = clinetId,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            RedirectUri = redirectUri,
            Expiry = DateTime.Now.AddMinutes(5)
        };
        
        // ჯსონ სტრინგში გადაგვყავს, რომ ქუერი პარამეტრში გავატანოთ.
        var codeString = protector.Protect(JsonSerializer.Serialize(code));
        
        return Results.Redirect(
            $"{redirectUri}?code={codeString}&state={state}&iss={iss}");
    }
}