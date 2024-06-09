var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie").AddCookie("cookie", o =>
{
    o.LoginPath = "/login";
});

builder.Services.AddAuthorization();
builder.Services.AddSingleton<DevKeys>();

public class DevKeys
{
}