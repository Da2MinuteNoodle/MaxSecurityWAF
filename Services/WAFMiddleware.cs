using System.Data;
using System.Text;
using System.Text.RegularExpressions;

namespace MaxSecurityWAF.Services;

public class WAFMiddleware {
    private readonly Regex SqlRegex = new(
        @"((SELECT|INSERT|UPDATE)\s+.+\s+(FROM|INTO|SET)\s+.+\b)|((ALTER|DROP)\s+TABLE\s+)|(GRANT\s+.+\s+ON\s+.+\s+TO\s+)|([0-9'];)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private readonly Regex XssRegex = new(
        @"(<\/?(script|a)>)|(javascript:)|(" + XssMagicPattern + ")",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private const string XssMagicString =
        @"cGhvbmUtaG9tZS14c3M=";

    private IWAFMiddlewareService middlewareService;

    private readonly ILogService logService;

    private RequestDelegate next;

    public WAFMiddleware(
        IWAFMiddlewareService middlewareService,
        RequestDelegate next,
        ILogService logService) {

        this.middlewareService = middlewareService;
        this.next              = next;
        this.logService        = logService;
    }

    public async Task<bool> ContainsSql(HttpRequest request) {
        if (!request.HasFormContentType)
            return false;

        request.EnableBuffering();
        var form = await request.ReadFormAsync();
        request.Body.Seek(0, SeekOrigin.Begin);

        return form.Any(kv => kv.Value.Any(v => v is null ? false : SqlRegex.IsMatch(v)));
    }

    public async Task<bool> ContainsXss(HttpRequest request) {
        if(!request.HasFormContentType)
            return false;

        request.EnableBuffering();
        var form = await request.ReadFormAsync();
        request.Body.Seek(0, SeekOrigin.Begin);

        var getMatches =
            request.Query.Any(kv => kv.Value.Any(v => v is null ? false : XssRegex.IsMatch(v)));
        var formMatches =
            form.Any(kv => kv.Value.Any(v => v is null ? false : XssRegex.IsMatch(v)));
        var xssMatches =
            XssRegex.IsMatch(request.Path.ToString().ToLower());

        Console.WriteLine($"\x1B[31m{request.Path.ToString().ToLower()}\x1B[0m");

        return getMatches || formMatches || xssMatches;
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

        bool block = !allow && !noAllowRules || deny;

        if(await ContainsSql(context.Request))
            block = true;
        if(await ContainsXss(context.Request))
            block = true;

        if(block) {
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

    private static string XssMagicPattern =>
        Encoding.UTF8.GetString(Convert.FromBase64String(XssMagicString));
}
