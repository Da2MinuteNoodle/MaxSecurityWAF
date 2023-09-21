namespace MaxSecurityWAF.Logging
{
    public class LogService
    {
        private List<LogEntry> logEntries = new List<LogEntry>();

        public void AddLogEntry(LogEntry entry)
        {
            logEntries.Add(entry);
        }
        public List<LogEntry> GetFilteredLogs(string filter)
        {
            return logEntries.Where(entry =>
                entry.SourceIP.Contains(filter) ||
                entry.Url.Contains(filter) ||
                entry.Outcome.Contains(filter))
                .ToList();
        }
        public List<LogEntry> GetLogEntries()
        {
            return logEntries;
        }
    }
}
