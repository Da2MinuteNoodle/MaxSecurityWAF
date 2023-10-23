using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace MaxSecurityWAF.Controllers;

[Controller]
public class LoginController : Controller {
    private IHttpContextAccessor httpContextAccessor;
    private IDbContextFactory<WAFContext> dbFactory;

    public LoginController(
        IHttpContextAccessor httpContextAccessor,
        IDbContextFactory<WAFContext> dbFactory) {

        this.httpContextAccessor = httpContextAccessor;
        this.dbFactory           = dbFactory;
    }

    // Ronald & Nitzan login

    [HttpPost("/Login")]
    public async Task<IActionResult> LoginAsync(
        [FromForm] string username,
        [FromForm] string password) {

        username = username.ToLower().Trim();

        using var db = dbFactory.CreateDbContext();
      
        var user = db.Users.FirstOrDefault(u => u.Username == username);
        if(user is null)
            return StatusCode(403);

        if(MaxSecurityWAF.User.HashPassword(password) != user.Password)
            return StatusCode(403);

        var claims = new Claim[] {
            new Claim(ClaimTypes.Name, username)
        };

        var claimsIdentity = new ClaimsIdentity(
            claims,
            CookieAuthenticationDefaults.AuthenticationScheme);

        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        await httpContextAccessor.HttpContext!.SignInAsync(claimsPrincipal);

        return Redirect("/Admin/Logs");
    }

    [HttpGet("/Logout")]
    public async Task<IActionResult> LogoutAsync() {
        await httpContextAccessor.HttpContext!.SignOutAsync();
        return Redirect("/Login");
    }
}
