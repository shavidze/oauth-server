using OAuthServer.Endpoints.OAuth;
using OAuthServer.Endpoints.OAuth.OAuth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie").AddCookie("cookie", o =>
{
    o.LoginPath = "/login";
});

builder.Services.AddAuthorization();
builder.Services.AddSingleton<DevKeys>();

var app = builder.Build();

app.MapGet("/login", GetLogin.Hanlder);
app.MapPost("/login", Login.Handler);
app.MapGet("/oauth/authorization", AuthorizationEndpoint.Handle).RequireAuthorization();
app.MapGet("/oauth/token", TokenEndpoint.Handle);


public class DevKeys
{
}