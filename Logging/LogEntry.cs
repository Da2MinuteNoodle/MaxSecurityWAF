namespace MaxSecurityWAF.Logging
{
    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public string SourceIP { get; set; }
        public string Url { get; set; }
        public string Outcome { get; set; }
    }
}
