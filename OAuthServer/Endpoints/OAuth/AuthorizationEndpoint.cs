using System.Web;
using Microsoft.AspNetCore.DataProtection;

namespace OAuthServer.Endpoints.OAuth.OAuth;

public static class AuthorizationEndpoint
{
    public static IResult Handle(HttpRequest request,IDataProtectionProvider dataProtectionProvider)
    {
        request.Query.TryGetValue("response_type", out var response_type);
        request.Query.TryGetValue("client_id", out var client_id);
        request.Query.TryGetValue("client_secret", out var client_secret);
        request.Query.TryGetValue("code_challenge", out var code_challenge);
        request.Query.TryGetValue("code_challenge_method", out var code_challenge_method);
        request.Query.TryGetValue("redirect_uri", out var redirect_uri);
        request.Query.TryGetValue("scope", out var scope);

        // state არის უნიკალური მნიშვნელობა, რომელიც თავიდან იქმნება კლიენტის მხრიდან,რომ
        // სერვერიდან მოსული ინფორმაცია, დაადასტუროს რომ ნამდვილად იმ სერვერიცსაა რომელსაც ელეპარაკება
        // ავტორიზაციის სერვერი, ბოლოს ამ მნიშნველობასაც უბრუნებს ქოლ ბექის ქუერი პარამეტრში უზერ აგენტს, და აგენტი კლიენტს.
        request.Query.TryGetValue("state", out var state);

        /*
         * დავაგენერიროთ კოდი
         */
        var protector = dataProtectionProvider.CreateProtector("oauth");
        var code = new AuthCode()
        {
            ClientId = client_id,
            CodeChallenge = code_challenge,
            CodeChallengeMethod = code_challenge_method,
            RedirectUri = redirect_uri,
            Expiry = DateTime.Now.AddMinutes(5)
        };
        
        return Results.Redirect(
            $"{redirect_uri}?code={}&state={state}&iss={HttpUtility.UrlEncode("https://localhost:5247")}");
    }
}