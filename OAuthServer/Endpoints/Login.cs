using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace OAuthServer.Endpoints.OAuth;

public static class Login
{
    public static async Task<IResult> Handler(HttpContext context, string returnUrl)
    {
        await context.SignInAsync("cookie", new ClaimsPrincipal(
            new ClaimsIdentity(
                new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
                }, "cookie")));
        
        // ეს რეზალტ კლასი, ენკაფსულაციას უკეთბს რესპონს, რომელიც უნდა გავაგზავნოთ კლიენტზე.
        // ეს 302, დააბრუნებს და გაატანს `returnUrl`-ს თუ სად წავიდეს.
        return Results.Redirect(returnUrl);
    }
}