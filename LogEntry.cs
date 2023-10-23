using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MaxSecurityWAF;

public enum LogResult {
    Allowed,
    Dropped,
    Rejected
}

// Ronald Logging Module

[Index(nameof(Timestamp))]
public class LogEntry {
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int       LogEntryId { get; set; }
    public DateTime  Timestamp  { get; set; }
    public string    SourceIP   { get; set; }
    public string    Url        { get; set; }
    public LogResult Result     { get; set; }
}
