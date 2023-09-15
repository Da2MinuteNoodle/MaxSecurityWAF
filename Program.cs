using MaxSecurityWAF;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.EntityFrameworkCore;
using Yarp.ReverseProxy.Transforms;

public class Program {
    public static void Main(string[] args) {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddDbContextFactory<WAFContext>();
        builder.Services.AddRazorPages();
        builder.Services.AddServerSideBlazor();
        builder.Services.AddSingleton<IWAFMiddlewareService, WAFMiddlewareService>();
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

        // Ensure the DB is created and it's schema is up to date
        var scope = app.Services.CreateScope();
        using var db = scope.ServiceProvider.GetRequiredService<WAFContext>();
        db.Database.Migrate();

        app.UseHsts();
        app.UseHttpsRedirection();

        app.UseStaticFiles();
        app.UseRouting();

        app.MapBlazorHub();
        app.MapFallbackToPage("/_Host");

        app.MapReverseProxy();
        app.UseMiddleware<WAFMiddleware>();

        app.Run();
    }
}
