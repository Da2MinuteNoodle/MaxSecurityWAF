namespace MaxSecurityWAF;

public class LogService {
    public event EventHandler LogUpdated;

    private List<LogEntry> logEntries = new List<LogEntry>();

    public void AddLogEntry(LogEntry entry) {
        logEntries.Add(entry);
        // Notify all pages that the contents of the log has changed
        // and that they should re-render. Do this AFTER committing
        // changes to the log itself to preserve log integrity in the
        // event of a failure/crash.
        LogUpdated?.Invoke(this, new());
    }

    public List<LogEntry> GetFilteredLogs(string filter) =>
        logEntries.Where(entry =>
            entry.SourceIP.Contains(filter) ||
            entry.Url.Contains(filter) ||
            entry.Result.ToString().Contains(filter))
            .ToList();

    public List<LogEntry> LogEntries => logEntries;
}
