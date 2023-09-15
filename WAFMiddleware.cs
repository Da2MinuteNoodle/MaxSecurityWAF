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

    private const string SqlInjectionPattern =
        @"(\s*([\0\b\'\""""\n\r\t\%_\\]*\s*(((select\s*.+\s*from\s*.+)|(insert\s*.+\s*into\s*.+)|(update\s*.+\s*set\s*.+)|(delete\s*.+\s*from\s*.+)|(drop\s*.+)|(truncate\s*.+)|(alter\s*.+)|(exec\s*.+)|(\s*(all|any|not|and|between|in|like|or|some|contains|containsall|containskey)\s*.+[\=\>\<=\!\~]+.+)|(let\s+.+[\=]\s*.*)|(begin\s*.*\s*end)|(\s*[\/\*]+\s*.*\s*[\*\/]+)|(\s*(\-\-)\s*.*\s+)|(\s*(contains|containsall|containskey)\s+.*)))(\s*[\;]\s*)*)+)";

    private Regex sqlInjectionRegex;

    public WAFMiddleware(IWAFMiddlewareService middlewareService, RequestDelegate next) {
        this.middlewareService = middlewareService;
        this.next              = next;

        sqlInjectionRegex = new(SqlInjectionPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
    }

    public async Task<bool> SqlInjectionFilter(HttpResponse response) {
        try {
            var originalContent = await new StreamReader(response.Body).ReadToEndAsync();

            if(originalContent is null)
                return false;

            return sqlInjectionRegex.IsMatch(originalContent);
        } catch {
            return false;
        }
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

        if((!allow && !noAllowRules) || deny)
            goto Reject;

        if(await SqlInjectionFilter(context.Response)) {
            context.Response.StatusCode = 403;
        }

        await next(context);

    Reject:
        context.Response.StatusCode = 403;
    }
}
