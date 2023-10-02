using Microsoft.EntityFrameworkCore;
using System.Data;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace MaxSecurityWAF;

public interface IWAFMiddlewareService {
    public WAFRule[] Rules { get; }
    public void Reload();
}

public class WAFMiddlewareService : IWAFMiddlewareService {
    public WAFRule[] Rules { get; private set; }

    private IDbContextFactory<WAFContext> dbFactory;

    public WAFMiddlewareService(IDbContextFactory<WAFContext> dbFactory) {
        this.dbFactory = dbFactory;
        Reload();
    }

    public void Reload() {
        using var db = dbFactory.CreateDbContext();
        Rules = db.Rules.ToArray();
    }

}
public class WAFMiddleware {
    private IWAFMiddlewareService middlewareService;

    private readonly RequestDelegate _next;

    private readonly LogService logService;

    private RequestDelegate next;


    public WAFMiddleware(
        IWAFMiddlewareService middlewareService,
        RequestDelegate next,
        LogService logService) {

        this.middlewareService = middlewareService;
        this.next              = next;
        this.logService        = logService;
    }

    public async Task InvokeAsync(HttpContext context) {
        // Don't bother filtering requests that aren't targetted
        // at WebGoat
        if(!context.Request.Path.ToString().ToLower().StartsWith("/webgoat")) {
            await next(context);
            return;
        }

        bool deny = middlewareService.Rules
            .Where(r => r.Action == WAFRuleAction.Deny)
            .Any(r => r.IsMatch(context.Request));

        bool allow = middlewareService.Rules
            .Where(r => r.Action == WAFRuleAction.Allow)
            .Any(r => r.IsMatch(context.Request));

        bool noAllowRules = !middlewareService.Rules
            .Select(r => r.Action)
            .Contains(WAFRuleAction.Allow);

        var logEntry = new LogEntry {
            Timestamp = DateTime.UtcNow,
            SourceIP  = context.Connection.RemoteIpAddress!.ToString(),
            Url       = context.Request.Path,
        };

        if((!allow && !noAllowRules) || deny) {
            // We decided to block the request
            context.Response.StatusCode = 403;
            logEntry.Result = LogResult.Rejected;
        } else {
            // We decided to allow the request
            logEntry.Result = LogResult.Allowed;
            await next(context);
        }

        logService.AddLogEntry(logEntry);
    }
}
