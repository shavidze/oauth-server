using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie").AddCookie("cookie").AddOAuth("custom", o =>
{
    // როდესაც ტოკენს დავითრევთ, და უზერის შესახებ დაგვჭირდება ინფორმაციის წამოღება და წამოვიღებთ გიტჰაბიდან `backchannel`-ით
    // მერე გამოვიყენებთ `cookie` აუთენტიფიკაციას, დავაგენერირებთ ქქუქის და მივცეთ უკან უზერ აგენტს = ბრაუზერს.
    o.SignInScheme = "cookie";

    o.ClientId = "x";
    o.ClientSecret = "x";

    o.AuthorizationEndpoint = "https://localhost:5002/oauth/authorize";
    o.TokenEndpoint = "https://localhost:5002/oauth/token";
    o.CallbackPath = "/oauth/custom-cb";

    o.UsePkce = true;
    o.ClaimActions.MapJsonKey("sub", "sub");
    o.Events.OnCreatingTicket = async context =>
    {
        //todo: map claims
    };
});

var app = builder.Build();

app.MapGet("/", (HttpContext context) => { return context.User.Claims.Select(x => new { x.Type, x.Value }).ToList(); });

/*
 * ესეიგი, აქ ვაჩელენგებთ უზერს, რომ გაიაროს აუთენტიფიკაცია, მითითებული აუთენტიკაციის სქემით,
 * ამ შემთხვევაში, `custom` სქემით, რომელიც აღვწერეთ ზემოთ არის `oauth` პროტოკოლის სქემა.
 */
app.MapGet("/login", () => Results.Challenge(new AuthenticationProperties()
    {
        RedirectUri = "https://localhost:5002/"
    },
    authenticationSchemes: new [] { "custom" }));

app.Run();