using Microsoft.EntityFrameworkCore;
using System.Net;

namespace MaxSecurityWAF.Services;

public interface IWAFMiddlewareService {
    public WAFRule[] Rules { get; }
    public IEnumerable<IPAddress> BlacklistedAddresses { get; }
    public event EventHandler OnBlacklistChange;

    public bool IsBlacklisted(IPAddress address);
    public void RecordBadRequest(HttpContext context);
    public void RemoveBlacklistEntry(IPAddress address);

    public void Reload();
}

// Max Middleware Service
public class WAFMiddlewareService : IWAFMiddlewareService {
    // Maximum number of offending requests before a client is blacklisted
    public const int MaxBlacklistCount = 3;

    public readonly TimeSpan BlackFlushInterval = TimeSpan.FromSeconds(30);

    public WAFRule[] Rules { get; private set; } = Array.Empty<WAFRule>();

    public List<BlacklistEntry> Blacklist { get; set; } = new();

    public event EventHandler OnBlacklistChange;

    private IDbContextFactory<WAFContext> dbFactory;

    public WAFMiddlewareService(IDbContextFactory<WAFContext> dbFactory) {
        this.dbFactory = dbFactory;

        Reload();
    }

    // Max & Laiba Blacklistign
    public bool IsBlacklisted(IPAddress address) =>
        Blacklist.Any(e => e.Count > MaxBlacklistCount && e.IPAddress == address);

    public void RecordBadRequest(HttpContext context) {
        var ip = context.Connection.RemoteIpAddress!;

        lock(Blacklist) {
            var entry = Blacklist.Find(e => e.IPAddress == ip);
            if(entry is null) {
                entry = new() {
                    IPAddress = ip,
                    Count     = 1
                };
                Blacklist.Add(entry);
            }
            entry.Count++;
        }

        OnBlacklistChange?.Invoke(this, new());
    }

    public void RemoveBlacklistEntry(IPAddress address) =>
        Blacklist.Remove(
            Blacklist.First(e => e.IPAddress == address && e.Count > MaxBlacklistCount));

    public IEnumerable<IPAddress> BlacklistedAddresses =>
        Blacklist.Select(e => e.IPAddress);

    public void Reload() {
        using var db = dbFactory.CreateDbContext();
        Rules = db.Rules.ToArray();
    }
}

public class BlacklistEntry {
    public IPAddress IPAddress { get; set; }
    public int       Count     { get; set; }
}
