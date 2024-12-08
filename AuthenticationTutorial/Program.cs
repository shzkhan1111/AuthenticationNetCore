using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using System.Runtime.Intrinsics.Arm;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

const string AuthScheme = "cookie";
//const string AuthScheme2 = "cookie2";

//for the security for this cookie 
//makes available IDataProvider available you can use for encryption and decrpytion
//builder.Services.AddDataProtection();
//builder.Services.AddHttpContextAccessor();
//builder.Services.AddScoped<AuthService>();

//above get registered under the hood  of the below 

//written at compile time 
builder.Services.AddAuthentication("cookie")
    .AddCookie(AuthScheme);
//cookie is responsibel for loading and writing back the cookie 

builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy("eu passport" ,pb =>
    {
        pb.RequireAuthenticatedUser()
        .AddAuthenticationSchemes(AuthScheme)
        
        //custom flow for your authorization process
        .AddRequirements()
        .RequireClaim("passport_type", "eur");
    });
});//config layer , Rules for building up policies 


var app = builder.Build();

//create a middle ware

//app.Use((ctx, next) =>
//{
//    //set service from collection for ids 
//    var idp = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();
//    var protector = idp.CreateProtector("auth-cookie");

//    //get the cookie from the cont ext that was set via login 
//    var authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
//    var protectedpayload = authCookie?.Split("=").Last();
//    var payload = protector.Unprotect(protectedpayload);
//    var parts = payload?.Split(":");

//    var key = parts[0];
//    var value = parts[1];
//    //loaded the cookie and now we need to pass on the data we found  
//    //load the cookie in a new claims Identity 
//    var claims = new List<Claim>();
//    claims.Add(new Claim(key, value));
//    var identity = new ClaimsIdentity(claims);
//    ctx.User = new ClaimsPrincipal(identity);

//    return next();
//});
//replacement for the above code 
//use authentication

app.UseAuthentication();
app.UseAuthorization();
///use authorization is going to do all of the below 

app.Use((ctx, next) =>

{
    if (ctx.Request.Path.StartsWithSegments("/login"))
    {
        return next(); 
    }
    if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
    {
        //if not auth return 401 not 
        ctx.Response.StatusCode = 401;
        return Task.CompletedTask;

    }
    else if (!ctx.User.HasClaim("passport_type", "eur"))
    {
        ctx.Response.StatusCode = 403;
        return Task.CompletedTask;
    }
    return next();
});

app.MapGet("/username",
        (HttpContext ctx) =>
        {
            return ctx.User.FindFirst("usr").Value; 
        }
    );


//issue a cookie 
app.MapGet("/login", async (HttpContext ctx) => 
        {
            //auth.SignIn();
            //await ctx
            //sign in with a scheme 
            var claims = new List<Claim>();
            claims.Add(new Claim("usr", "KingShah"));
            claims.Add(new Claim("passport_type", "eur"));
            var identity = new ClaimsIdentity(claims, "cookie");
            var user = new ClaimsPrincipal( identity );
            await ctx.SignInAsync(AuthScheme, user);
            return "some name";
        }
    );

app.MapGet("/unsecure", (HttpContext ctx) =>
{

    return ctx.User.FindFirst("usr")?.Value ?? "empty";
}).RequireAuthorization("eu passport");

app.MapGet("/sweden", (HttpContext ctx) =>
{

    //if (!ctx.User.HasClaim("passport_type" , "eur"))
    //{
    //    ctx.Response.StatusCode = 403;
    //    return "";
    //}
    //else
    //{
    //    //ctx.Response.StatusCode = 403;
    return "allowed";
    //}

}).RequireAuthorization("eu passport"); ;

//[AuthScheme(AuthScheme2)]
app.MapGet("/denmark", (HttpContext ctx) =>
{
    //if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
    //{
    //    ctx.Response.StatusCode = 401;
    //    return "";

    //}
    //else if (!ctx.User.HasClaim("passport_type", "eur"))
    //{
    //    ctx.Response.StatusCode = 403;
    //    return "";
    //}
    //else
    //{
    //    //ctx.Response.StatusCode = 403;
    return "allowed";
    //}

}).RequireAuthorization("eu passport"); ;



app.Run();

    //public class AuthService
    //{
    //    private readonly IDataProtectionProvider _idp;
    //    private readonly IHttpContextAccessor _accessor;
    //    public AuthService(IDataProtectionProvider idp , IHttpContextAccessor accessor)
    //    {
    //        _idp = idp;
    //        _accessor = accessor;
    //    }

    //    public void SignIn()
    //    {
    //        var protector = _idp.CreateProtector("auth-cookie");
    //        //in response we are setting up the cookie
    //        _accessor.HttpContext.Response.Headers["set-cookie"] = $"auth={protector.Protect("usr:shahzaib")}";
    //    }
    
    //}



public class MyRequirement : IAuthorizationRequirement
{

}
public class MyRequirementHandler : AuthorizationHandler<MyRequirement>
{
    public MyRequirementHandler()
    {
        //any Auth logic can be used inside this class 
        //applied to any end point 
        //Add 
    }
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MyRequirement requirement)
    {
        //context.User
        //context.Succeed(new MyRequirement());
        return Task.CompletedTask;
    }
}