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

    private RequestDelegate next;

    public WAFMiddleware(IWAFMiddlewareService middlewareService, RequestDelegate next) {
        this.middlewareService = middlewareService;
        this.next = next;
    }

    public async Task InvokeAsync(HttpContext context) {
        bool deny = middlewareService.Rules
            .Where(r => r.Action == WAFRuleAction.Deny)
            .Any(r => r.IsMatch(context.Request));

        bool allow = middlewareService.Rules
            .Where(r => r.Action == WAFRuleAction.Allow)
            .Any(r => r.IsMatch(context.Request));

        bool noAllowRules = !middlewareService.Rules
            .Select(r => r.Action)
            .Contains(WAFRuleAction.Allow);

        if((!allow && !noAllowRules) || deny) {
            context.Response.StatusCode = 403;
            return;
        }

        await next(context);
    }
}
