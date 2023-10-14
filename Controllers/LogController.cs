using MaxSecurityWAF.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MaxSecurityWAF.Controllers;

[Controller]
public class LogController : Controller {
    private ILogService logService;

    public LogController(ILogService logService) =>
        this.logService = logService;

    [HttpGet("/Admin/Logs.csv")]
    public async Task<IActionResult> LogCsv() {
        var log = logService.LogEntries.Select(l => string.Join(',', new string[] {
            l.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
            l.SourceIP,
            l.Url,
            l.Result.ToString() }));

        return File(
            Encoding.UTF8.GetBytes(string.Join('\n', log)),
            "text/csv",
            $"{BaseFilename}.csv");
    }

    [HttpGet("/Admin/Logs.json")]
    public async Task<IActionResult> LogJson() {
        return File(
            Encoding.UTF8.GetBytes(
                JsonSerializer.Serialize(logService.LogEntries, new JsonSerializerOptions() {
                    Converters = {
                        new JsonStringEnumConverter(JsonNamingPolicy.CamelCase)
                    }
                })),
            "application/json",
            $"{BaseFilename}.json");
    }

    private string BaseFilename =>
        $"{DateTime.Now.ToString("yyyy-MM-dd HH:mm")} WAF Log";
}
