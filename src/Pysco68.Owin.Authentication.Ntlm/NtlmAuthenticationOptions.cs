﻿namespace Pysco68.Owin.Authentication.Ntlm
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
#if NETFULL
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
#endif
    using Pysco68.Owin.Authentication.Ntlm.Security;
    using System.Security.Claims;
    using System.Security.Principal;
#if NETCORE2_0
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Authentication;
#endif

    public class NtlmAuthenticationOptions :
#if NETFULL
        AuthenticationOptions
#elif NETCORE2_0
        RemoteAuthenticationOptions
#endif
    {
        #region Internal fields
        /// <summary>
        /// The default redirection path used by the NTLM authentication middleware of
        /// the full roundtrip / handshakes
        /// </summary>
        internal static readonly PathString DefaultRedirectPath = new PathString("/authentication/ntlm-signin");

        /// <summary>
        /// Secured store for state data
        /// </summary>
        internal ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        
        /// <summary>
        /// Store states for the login attempts
        /// </summary>
        internal StateCache LoginStateCache { get; set; }
        #endregion

        /// <summary>
        /// Number of minutes a login can take (defaults to 2 minutes)
        /// </summary>
        public int LoginStateExpirationTime
        {
            set { LoginStateCache.ExpirationTime = value; }
            get { return LoginStateCache.ExpirationTime; }
        }

        /// <summary>
        /// The authentication type used for sign in
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

#if NETFULL
        /// <summary>
        /// The callback string used for the NTLM authentication roundtrips, 
        /// defaults to "/authentication/ntlm-signin"
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// If this is set, it must return true to authenticate the user.
        /// It can be used to filter out users according to separate criteria.
        /// </summary>
        /// <remarks>
        /// Note that the Windows identity will be disposed shortly after this function has returned
        /// </remarks>
        public Func<WindowsIdentity, IOwinRequest, bool> Filter { get; set; }

        /// <summary>
        /// This is fired when a valid WindowsIdentity has been found, and must return a ClaimsIdentity
        /// 
        /// parameter 1: the newly created windows identiy
        /// parameter 2: the options object of the middleware
        /// parameter 3: the current request
        /// </summary>
        public Func<WindowsIdentity, NtlmAuthenticationOptions, IOwinRequest, ClaimsIdentity> OnCreateIdentity { get; set; }

        /// <summary>
        /// Creates an instance of Ntlm authentication options with default values.
        /// </summary>
        public NtlmAuthenticationOptions()
            : base(NtlmAuthenticationDefaults.AuthenticationType)
        {
            this.AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Passive;
            this.CallbackPath = NtlmAuthenticationOptions.DefaultRedirectPath;
            this.LoginStateCache = new StateCache("NtlmAuthenticationStateCache");
            this.LoginStateExpirationTime = 2;
        }
#elif NETCORE2_0
        /// <summary>
        /// If this is set, it must return true to authenticate the user.
        /// It can be used to filter out users according to separate criteria.
        /// </summary>
        /// <remarks>
        /// Note that the Windows identity will be disposed shortly after this function has returned
        /// </remarks>
        public Func<WindowsIdentity, HttpRequest, bool> Filter { get; set; }

        /// <summary>
        /// This is fired when a valid WindowsIdentity has been found, and must return a ClaimsIdentity
        /// 
        /// parameter 1: the newly created windows identiy
        /// parameter 2: the options object of the middleware
        /// parameter 3: the current request
        /// </summary>
        public Func<WindowsIdentity, NtlmAuthenticationOptions, HttpRequest, ClaimsIdentity> OnCreateIdentity { get; set; }

        public string AuthenticationType { get; set; } = NtlmAuthenticationDefaults.AuthenticationType;

        /// <summary>
        /// Creates an instance of Ntlm authentication options with default values.
        /// </summary>
        public NtlmAuthenticationOptions()
        {
            this.CallbackPath = NtlmAuthenticationOptions.DefaultRedirectPath;
            this.LoginStateCache = new StateCache("NtlmAuthenticationStateCache");
            this.LoginStateExpirationTime = 2;
        }
#endif
    }

    public static class NtlmAuthenticationDefaults
    {
        public const string DisplayName = "NTLM";
        public const string AuthenticationType = "Ntlm";
    }
}
