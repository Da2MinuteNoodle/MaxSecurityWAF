using MaxSecurityWAF;
using MaxSecurityWAF.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using System.Net;
using Yarp.ReverseProxy.Transforms;


// Team Boilerplate code
public class Program {
    public static void Main(string[] args) {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddHttpContextAccessor();
        builder.Services.AddAuthentication(
            CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
        builder.Services.AddDbContextFactory<WAFContext>();
        builder.Services.AddControllers();
        builder.Services.AddRazorPages();
        builder.Services.AddServerSideBlazor();
        builder.Services.AddSingleton<IWAFMiddlewareService, WAFMiddlewareService>();
        builder.Services.AddSingleton<ILogService, LogService>();
        builder.Services.Configure<ForwardedHeadersOptions>(options => {
            options.ForwardLimit = 2;
            options.KnownProxies.Add(IPAddress.Parse("10.10.0.23"));
            options.ForwardedForHeaderName = "X-Forwarded-For";
        });

        // Max's reverse proxy functionality
        builder.Services.AddReverseProxy()
            .AddTransforms(builderContext => {
                builderContext.AddResponseTransform(bc => {
                    var headers = bc.HttpContext.Response.Headers;
                    if(!headers.TryGetValue("Location", out var locations))
                        return ValueTask.CompletedTask;
                    headers.Remove("Location");
                    headers.Add(
                        "Location",
                        locations[0]!.Replace("http://127.0.0.1:8080/", "/"));
                    return ValueTask.CompletedTask;
                });
            })
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

        var app = builder.Build();


        // Laiba DB code
        // Ensure the DB is created and it's schema is up to date
        var scope = app.Services.CreateScope();
        using var db = scope.ServiceProvider.GetRequiredService<WAFContext>();
        db.Database.Migrate();

        app.UseAuthentication();
        app.UseHsts();
        app.UseHttpsRedirection();
        app.UseStaticFiles();
        app.UseRouting();
        app.MapControllers();
        app.MapBlazorHub();
        app.MapFallbackToPage("/_Host");

        app.MapReverseProxy();
        app.UseMiddleware<ForwardedHeadersMiddleware>();
        app.UseMiddleware<WAFMiddleware>();

        app.Run();
    }
}
