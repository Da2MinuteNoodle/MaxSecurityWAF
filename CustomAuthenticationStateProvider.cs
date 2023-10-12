using System;
using System.Net.NetworkInformation;
using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims; 

namespace MaxSecurityWAF;

	public class CustomAuthenticationStateProvider : AuthenticationStateProvider
{

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
       // throw new NotImplementedException();

        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "admin"), }, "apiauth_type");

        var user = new ClaimsPrincipal(identity);

        return Task.FromResult(new AuthenticationState(user)); 
    }

    public void MarkUserAsAuthenticated(string username)
    {
        var identity = new ClaimsIdentity(new[]
       {
            new Claim(ClaimTypes.Name, username), }, "apiauth_type");

        var user = new ClaimsPrincipal(identity);

        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
    }
}

