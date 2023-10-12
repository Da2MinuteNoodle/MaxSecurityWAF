using Microsoft.AspNetCore.Components;
using Microsoft.EntityFrameworkCore;
using System.Collections.Specialized;

namespace MaxSecurityWAF.Services;

public interface ILogService {
    public IEnumerable<LogEntry> LogEntries { get; }

    public event EventHandler<LogEntry>? LogUpdated;

    public void AddLogEntry(LogEntry entry);
    public IEnumerable<LogEntry> GetFilteredLogs(string filter);
}

public class LogService : ILogService, IDisposable {
    // Maximum amount of time to keep log entries before they must
    // be flushed to the DB
    private readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(30);

    // Maximum number of log entries to keep before flushing to the DB
    private const int MaxDirtyLogEntries = 1000;

    public event EventHandler<LogEntry>? LogUpdated;

    // Maintain a local write-cache to avoid running an expensive SQL
    // query for each HTTP request we process.
    private List<LogEntry> writeCache = new List<LogEntry>();

    private Timer writebackTimer;

    private IDbContextFactory<WAFContext> dbFactory;

    public LogService(IDbContextFactory<WAFContext> dbFactory) {
        this.dbFactory = dbFactory;

        writebackTimer = new((o) => Flush());
        writebackTimer.Change(FlushInterval, FlushInterval);
    }

    public void AddLogEntry(LogEntry entry) {
        entry.Timestamp = DateTime.SpecifyKind(entry.Timestamp, DateTimeKind.Utc);

        int count;

        lock(writeCache) {
            writeCache.Add(entry);
            count = writeCache.Count();
        }

        if(count > MaxDirtyLogEntries)
            Flush();

        // Notify all pages that the contents of the log has changed
        // and that they should re-render. Do this AFTER committing
        // changes to the log itself to preserve log integrity in the
        // event of a failure/crash.
        LogUpdated?.Invoke(this, entry);
    }

    public IEnumerable<LogEntry> GetFilteredLogs(string filter) {
        Flush();

        using var db = dbFactory.CreateDbContext();

        var entries = db.LogEntries
            .OrderByDescending(e => e.Timestamp)
            .Where(e =>
                e.SourceIP.Contains(filter) ||
                e.Url.Contains(filter) ||
                e.Result.ToString().Contains(filter));

        foreach(var entry in entries)
            yield return entry;
    }

    public IEnumerable<LogEntry> LogEntries {
        get {
            Flush();
            using var db = dbFactory.CreateDbContext();
            foreach(var entry in db.LogEntries.OrderByDescending(e => e.Timestamp))
                yield return entry;
        }
    }

    // We flush the write-cache before querying the DB to avoid
    // an expensive merge and sort operation locally. Let the DB
    // do it much faster than we can...
    private void Flush() {
        using var db = dbFactory.CreateDbContext();

        lock(writeCache) {
            db.LogEntries.AddRange(writeCache);
            writeCache.Clear();
        }
    }

    public void Dispose() =>
        writebackTimer.Dispose();
}
