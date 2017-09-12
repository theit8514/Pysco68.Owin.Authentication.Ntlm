using NUnit.Framework;
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

#if NETFULL
using Microsoft.Owin.Hosting;
using Microsoft.Owin.Testing;
#endif

#if NETCORE2_0
using System.IO;
using Microsoft.AspNetCore.Hosting;
#endif

namespace Pysco68.Owin.Authentication.Ntlm.Tests
{
    [TestFixture]
    public class AuthenticationTests
    {
        private IDisposable Server;
        private Uri BaseAddress;

        [OneTimeSetUp]
        public void Init()
        {
            this.BaseAddress = new Uri("http://localhost:9999");
#if NETFULL
            this.Server = WebApp.Start<WebApplication>(new StartOptions()
            {
                Port = 9999
            });
#endif
#if NETCORE2_0
            var host = new WebHostBuilder()
                .UseKestrel(options =>
                {
                    options.Listen(IPAddress.Any, 9999);
                })
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseStartup<WebApplication>()
                .Build();

#pragma warning disable 4014
            host.RunAsync();
#pragma warning restore 4014

            this.Server = host;
#endif
        }

        [OneTimeTearDown]
        public void Teardown()
        {
            this.Server.Dispose();
        }


        [Test]
        public async Task LogInSuccessfully()
        {
            var handler = new HttpClientHandler 
            { 
                AllowAutoRedirect = true, 
                Credentials = CredentialCache.DefaultNetworkCredentials
            };

            var client = new HttpClient(handler);            
            client.BaseAddress = this.BaseAddress;


            var response = await client.GetAsync("/api/test");
            var result = response.Content.ReadAsString();

            var currentUserName = Environment.UserName;

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, "Http status");
            Assert.AreEqual(currentUserName, result);            
        }

        [Test]
        public async Task LogInFail()
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = true,
            };

            var client = new HttpClient(handler);
            var address = new UriBuilder(this.BaseAddress);
#if NETCORE
            // Use local machine name due to: https://github.com/dotnet/corefx/issues/5045#issuecomment-190018811
            address.Host = Environment.MachineName;
#endif
            client.BaseAddress = address.Uri;

            var response = await client.GetAsync("/api/test");
            var result = response.Content.ReadAsString();

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, "Http status");
            Assert.That(result, Is.Null.Or.Empty, "Username should have been null");
        }


        [Test]
        public async Task LogInFailBecauseOfFilter()
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                Credentials = CredentialCache.DefaultNetworkCredentials
            };
            WebApplication.Options.Filter = (identity, request) => false;
            try
            {
                var client = new HttpClient(handler);
                client.BaseAddress = this.BaseAddress;

                var response = await client.GetAsync("/api/test");
                var result = response.Content.ReadAsString();

                Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, "Http status");
                Assert.That(result, Is.Null.Or.Empty, "Username should have been null");
            }
            finally
            {
                WebApplication.Options.Filter = null;
            }
        }
    }
}
