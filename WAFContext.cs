using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Net;
using System.Text.RegularExpressions;

namespace MaxSecurityWAF;

public class WAFContext : DbContext {
    public DbSet<WAFRule>  Rules      { get; set; } 
    public DbSet<User>     Users      { get; set; }
    public DbSet<LogEntry> LogEntries { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder options) =>
        options.UseSqlite($"Data Source={nameof(MaxSecurityWAF)}.db");

    protected override void OnModelCreating(ModelBuilder builder) {
        builder.Entity<User>().HasData(new[] {
            new User() {
                UserId   = -1,
                Username = "admin",
                Password = "admin"
            }
        });
    }
}

public enum WAFRuleAction {
    Deny  = 0,
    Allow = 1
}

public class WAFRule {
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int           WAFRuleId { get; set; }
    public bool          Enabled   { get; set; } = true;
    public WAFRuleAction Action    { get; set; }
    public string        Path      { get; set; }
    public IPAddress     SourceIP  { get; set; }

    private Regex? pathRegex;

    public bool IsMatch(HttpRequest request) {
        if(!Enabled)
            return false;

        if(pathRegex is null)
            pathRegex = new Regex(Path, RegexOptions.IgnoreCase | RegexOptions.Compiled);

        if(!pathRegex.IsMatch(request.Path))
            return false;

        if(SourceIP.Address == 0)
            return true;

        return SourceIP == request.HttpContext.Connection.RemoteIpAddress;
    }
}

[Index(nameof(Username))]
public class User {
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int    UserId   { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
}
