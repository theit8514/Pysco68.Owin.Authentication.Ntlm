using System;
#if NETFULL
using Owin;
using Microsoft.Owin.Extensions;
using Microsoft.Owin;
#endif

#if NETCORE
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
#endif

namespace Pysco68.Owin.Authentication.Ntlm
{
    public static class NtlmAuthenticationExtensions
    {
#if NET45
        /// <summary>
        /// Enable using Ntlm authentication
        /// </summary>
        /// <param name="app"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public static IAppBuilder UseNtlmAuthentication(this IAppBuilder app, NtlmAuthenticationOptions options = null)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            app.Use(typeof(NtlmAuthenticationMiddleware), app, options != null ? options : new NtlmAuthenticationOptions());
            app.UseStageMarker(PipelineStage.Authenticate);

            return app;
        }

        /// <summary>
        /// Check if the present request is actually a callpack path for the NTLM authentication middleware
        /// </summary>
        /// <remarks>
        /// If you didn't use the default redirection path in the configuration of the NTLM authentication 
        /// middleware you must supply the same path to this function. See overloads of this method.
        /// </remarks>
        /// <param name="request"></param>
        /// <returns>True if the request path is the callback path, false otherwise</returns>
        public static bool IsNtlmAuthenticationCallback(
            this IOwinRequest request)
        {
            return request.IsNtlmAuthenticationCallback(NtlmAuthenticationOptions.DefaultRedirectPath);
        }

        /// <summary>
        /// Check if the present request is actually a callpack path for the NTLM authentication middleware
        /// </summary>
        /// <param name="request"></param>
        /// <param name="redirectPath">The path to check against</param>
        /// <returns>True if the request path matches the callback path, false otherwise</returns>
        public static bool IsNtlmAuthenticationCallback(
            this IOwinRequest request, 
            PathString redirectPath)
        {
            return (request.PathBase.Add(request.Path) == redirectPath);
        }
#endif
#if NETCORE2_0
        public static AuthenticationBuilder AddNtlmAuthentication(this AuthenticationBuilder builder)
        {
            return builder.AddNtlmAuthentication(options => { });
        }

        public static AuthenticationBuilder AddNtlmAuthentication(this AuthenticationBuilder builder,
            Action<NtlmAuthenticationOptions> configureOptions)
        {
            return builder
                .AddNtlmAuthentication<NtlmAuthenticationOptions, NtlmAuthenticationHandler<NtlmAuthenticationOptions>>(
                    configureOptions);
        }

        public static AuthenticationBuilder AddNtlmAuthentication(this AuthenticationBuilder builder,
            string displayName, Action<NtlmAuthenticationOptions> configureOptions)
        {
            builder.Services
                .TryAddEnumerable(ServiceDescriptor
                    .Singleton<IPostConfigureOptions<NtlmAuthenticationOptions>,
                        NtlmAuthenticationPostConfigureOptions<NtlmAuthenticationOptions,
                            NtlmAuthenticationHandler<NtlmAuthenticationOptions>>>());
            return builder
                .AddRemoteScheme<NtlmAuthenticationOptions, NtlmAuthenticationHandler<NtlmAuthenticationOptions>>(
                    NtlmAuthenticationDefaults.AuthenticationType,
                    displayName,
                    configureOptions);
        }

        static AuthenticationBuilder AddNtlmAuthentication<TOptions, THandler>(
            this AuthenticationBuilder builder, Action<TOptions> configureOptions)
            where TOptions : NtlmAuthenticationOptions, new()
            where THandler : NtlmAuthenticationHandler<TOptions>
        {
            builder.Services
                .TryAddEnumerable(ServiceDescriptor
                    .Singleton<IPostConfigureOptions<TOptions>,
                        NtlmAuthenticationPostConfigureOptions<TOptions, THandler>>());
            return builder.AddRemoteScheme<TOptions, THandler>(NtlmAuthenticationDefaults.AuthenticationType,
                NtlmAuthenticationDefaults.DisplayName,
                configureOptions);
        }

        [Obsolete(
            "UseNtlmAuthentication is obsolete. Configure Ntlm authentication with AddAuthentication().AddNtlmAuthentication in ConfigureServices. See https://go.microsoft.com/fwlink/?linkid=845470 for more details.",
            true)]
        public static IApplicationBuilder UseNtlmAuthentication(this IApplicationBuilder app,
            NtlmAuthenticationOptions options = null)
        {
            throw new NotSupportedException(
                "This method is no longer supported, see https://go.microsoft.com/fwlink/?linkid=845470");
        }
#endif
    }
}
