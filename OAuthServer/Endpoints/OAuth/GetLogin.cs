using System.Web;

namespace OAuthServer.Endpoints.OAuth;

public static class GetLogin
{
    public static async Task Hanlder(string returnUrl, HttpResponse response)
    {
        response.Headers.ContentType = new string[] {  "text/html" };
        await response.WriteAsync($"""
                                   <html>
                                     <head>
                                        <title>Login</title>
                                     </head>
                                     <body>
                                        <form action = "/login?returnUrl={HttpUtility.UrlEncode(returnUrl)}" method = "post">
                                            <input value = "Submit" type="submit"/>
                                        </form>
                                     </body>
                                   </html>
                                   """);
    }
}