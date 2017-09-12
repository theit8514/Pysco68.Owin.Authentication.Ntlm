#if NETFULL
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using System.Web.Http;
#endif

#if NETCORE2_0
using System.IO;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
#endif

namespace Pysco68.Owin.Authentication.Ntlm.Tests
{
    class WebApplication
    {
        /// <summary>
        /// Note: static is okay here. DI would be significantly cruftier...
        /// </summary>
        public static NtlmAuthenticationOptions Options { get; private set; } = new NtlmAuthenticationOptions();

#if NETFULL
        public void Configuration(IAppBuilder app)
        {
            // use default sign in with application cookies
            app.SetDefaultSignInAsAuthenticationType("ApplicationCookie");

            // set up the cookie aut
            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                AuthenticationType = "ApplicationCookie",
                LoginPath = new PathString("/api/account/ntlmlogin"),
                ReturnUrlParameter = "redirectUrl",
                Provider = new CookieAuthenticationProvider()
                {
                    OnApplyRedirect = ctx =>
                    {
                        if (!ctx.Request.IsNtlmAuthenticationCallback())
                        {
                            ctx.Response.Redirect(ctx.RedirectUri);
                        }
                    }
                }
            });

            // Enable NTLM authentication
            app.UseNtlmAuthentication(Options);

            // configure web api
            var config = new HttpConfiguration();
            config.Routes.MapHttpRoute("DefaultApi", "api/{controller}/{id}", new { id = RouteParameter.Optional });

            app.UseWebApi(config);
        }
#endif
#if NETCORE2_0
        public WebApplication(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseAuthentication();
            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    "default",
                    "{controller}/{action=Index}/{id?}");

                routes.MapRoute(
                    "api",
                    "api/{controller}/{id?}",
                    new { action = "get" });
            });
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddLogging(builder =>
            {
                builder.AddConsole();
                builder.AddDebug();
            });
            const string cookie = "TestCookie";
            services.AddAuthentication(cookie)
                .AddCookie(cookie, options =>
                {
                    options.LoginPath = new PathString("/api/account/ntlmlogin");
                    options.ReturnUrlParameter = "redirectUrl";
                })
                .AddNtlmAuthentication(options =>
                {
                    Options = options;
                    options.SignInAsAuthenticationType = cookie;
                });
            services.AddMvc();
        }
#endif
    }

    /// <summary>
    /// Test controller returning the username if authentication succeeds!
    /// </summary>
    [Authorize]
    public class TestController :
#if NETFULL
        ApiController
#elif NETCORE2_0
        Controller
#endif
    {
#if NETFULL
        // GET /api/test
        public string Get()
        {
            if (User == null) return "Not authenticated!";

            return User.Identity.Name;
        }
#elif NETCORE2_0
        // GET /api/test
        public IActionResult Get()
        {
            if (User == null) return new ObjectResult("Not authenticated!");

            return new ObjectResult(User.Identity.Name);
        }
#endif
    }

    [Authorize]
#if NETFULL
    [RoutePrefix("api/account")]
#elif NETCORE2_0
    [Route("api/[controller]")]
#endif
    public class AccountController :
#if NETFULL
        ApiController
#elif NETCORE2_0
        Controller
#endif
    {
        public AccountController()
        {

        }

#if NETFULL
        [AllowAnonymous]
        [Route("ntlmlogin")]
        [HttpGet]
        public IHttpActionResult Ntlmlogin(string redirectUrl)
        {
            // create a login challenge if there's no user logged in!
            // Changed from checking User == null to IsAuthenticated
            // See https://github.com/aspnet/HttpAbstractions/commit/b751cf19d0b4b573dd0bdd558879e5128675e1df
            if (this.User?.Identity?.IsAuthenticated ?? false)
                return Redirect(redirectUrl);

            var ap = new AuthenticationProperties()
            {
                RedirectUri = redirectUrl
            };

            var context = this.Request.GetContext();
            context.Authentication.Challenge(ap, NtlmAuthenticationDefaults.AuthenticationType);
            return Unauthorized();
        }
#elif NETCORE2_0
        [AllowAnonymous]
        [Route("ntlmlogin")]
        [HttpGet]
        public IActionResult Ntlmlogin(string redirectUrl)
        {
            // create a login challenge if there's no user logged in!
            // Changed from checking User == null to IsAuthenticated
            // See https://github.com/aspnet/HttpAbstractions/commit/b751cf19d0b4b573dd0bdd558879e5128675e1df
            if (this.User?.Identity?.IsAuthenticated ?? false)
                return Redirect(redirectUrl);

            var ap = new AuthenticationProperties()
            {
                RedirectUri = redirectUrl
            };

            this.HttpContext.Response.StatusCode = 401;
            this.HttpContext.ChallengeAsync(NtlmAuthenticationDefaults.AuthenticationType, ap).Wait();
            return StatusCode(HttpContext.Response.StatusCode);
        }
#endif
    }
}
