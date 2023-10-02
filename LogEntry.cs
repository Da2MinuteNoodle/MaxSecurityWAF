namespace MaxSecurityWAF;

public enum LogResult {
    Allowed,
    Dropped,
    Rejected
}

public class LogEntry {
    public DateTime  Timestamp { get; set; }
    public string    SourceIP  { get; set; }
    public string    Url       { get; set; }
    public LogResult Result    { get; set; }
}
