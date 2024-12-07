using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Formatters;
using System.Runtime.Intrinsics.Arm;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

//for the security for this cookie 
//makes available IDataProvider available you can use for encryption and decrpytion
builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthService>();



var app = builder.Build();

//create a middle ware

app.Use((ctx, next) =>
{
    //set service from collection for ids 
    var idp = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();
    var protector = idp.CreateProtector("auth-cookie");

    //get the cookie from the cont ext that was set via login 
    var authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
    var protectedpayload = authCookie?.Split("=").Last();
    var payload = protector.Unprotect(protectedpayload);
    var parts = payload?.Split(":");

    var key = parts[0];
    var value = parts[1];
    //loaded the cookie and now we need to pass on the data we found  
    //load the cookie in a new claims Identity 
    var claims = new List<Claim>();
    claims.Add(new Claim(key, value));
    var identity = new ClaimsIdentity(claims);
    ctx.User = new ClaimsPrincipal(identity);

    return next();
});

app.MapGet("/username",
        (HttpContext ctx) =>
        {
            return ctx.User.FindFirst("usr").Value; 
        }
    );


//issue a cookie 
app.MapGet("/login",
        (AuthService auth , IDataProtectionProvider idp) =>
        {
            auth.SignIn();
            return "some name";
        }
    );

app.Run();

public class AuthService
{
    private readonly IDataProtectionProvider _idp;
    private readonly IHttpContextAccessor _accessor;
    public AuthService(IDataProtectionProvider idp , IHttpContextAccessor accessor)
    {
        _idp = idp;
        _accessor = accessor;
    }

    public void SignIn()
    {
        var protector = _idp.CreateProtector("auth-cookie");
        //in response we are setting up the cookie
        _accessor.HttpContext.Response.Headers["set-cookie"] = $"auth={protector.Protect("usr:shahzaib")}";
    }
    
}