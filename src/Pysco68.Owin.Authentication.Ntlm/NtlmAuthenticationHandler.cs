
namespace Pysco68.Owin.Authentication.Ntlm
{
#if NETFULL
    using Microsoft.Owin;
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;
    using Pysco68.Owin.Authentication.Ntlm.Helpers;
#endif
    using Pysco68.Owin.Authentication.Ntlm.Security;
    using System;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;
    using System.Security.Cryptography;
#if NETCORE2_0
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.Extensions.Options;
    using Microsoft.Extensions.Logging;
    using System.Text.Encodings.Web;
    using Microsoft.AspNetCore.WebUtilities;
#endif

#if NETFULL
    class NtlmAuthenticationHandler : AuthenticationHandler<NtlmAuthenticationOptions>
#elif NETCORE2_0
    class NtlmAuthenticationHandler<TOptions> : RemoteAuthenticationHandler<TOptions> where TOptions : NtlmAuthenticationOptions, new()
#endif
    {
#if NETFULL
        private readonly ILogger logger;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger"></param>
        public NtlmAuthenticationHandler(ILogger logger)
        {
            this.logger = logger;
        }

        public LogWrapper Logger => new LogWrapper(logger);
#elif NETCORE2_0
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="options"></param>
        /// <param name="logger"></param>
        /// <param name="encoder"></param>
        /// <param name="clock"></param>
        public NtlmAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }
#endif

        protected async Task<AuthenticationTicket> AuthenticateTicketAsync()
        {
            // note: this is cheating for async...
            AuthenticationProperties properties = await Task.FromResult<AuthenticationProperties>(null);
            HandshakeState state = null;

            // retrieve the state Id
#if NETFULL
            var stateId = Request.Query["state"];
#else
            var stateId = Request.Query["state"].ToString();
#endif


            if (!string.IsNullOrEmpty(stateId) && this.Options.LoginStateCache.TryGet(stateId, out state))
            {
                // okay, we shall authenticate! For that we must
                // get the authorization header and extract the token
#if NETFULL
                var authorizationHeader = Request.Headers["Authorization"];
#else
                var authorizationHeader = Request.Headers["Authorization"].ToString();
#endif

                byte[] token = null;
                if (!string.IsNullOrEmpty(authorizationHeader) && authorizationHeader.StartsWith("NTLM "))
                {
                    token = Convert.FromBase64String(authorizationHeader.Substring(5));
                }

                // First eight bytes are header containing NTLMSSP\0 signature
                // Next byte contains type of the message recieved.
                // No Token - it's the initial request. Add a authenticate header
                // Message Type 1 — is initial client's response to server's 401 Unauthorized error.
                // Message Type 2 — is the server's response to it. Contains random 8 bytes challenge.
                // Message Type 3 — is encrypted password hashes from client ready to server validation.
                if (token != null && token[8] == 1)
                {
                    // Message of type 1 was received
                    if (state.TryAcquireServerChallenge(ref token))
                    {
                        // send the type 2 message
                        var authorization = Convert.ToBase64String(token);
                        Response.Headers.Add("WWW-Authenticate", new[] {string.Concat("NTLM ", authorization)});
                        Response.StatusCode = 401;

                        // not sucessfull
                        Logger.LogInformation("Received valid NTLM Type 1, sent NTLM Type 2");
#if NETFULL
                        return new AuthenticationTicket(null, properties);
#elif NETCORE2_0
                        return null;
#endif
                    }
                    Logger.LogWarning("Received invalid NTLM Type 1, resending WWW-Authenticate");
                }
                else if (token != null && token[8] == 3)
                {
                    // message of type 3 was received
                    if (state.IsClientResponseValid(token))
                    {
                        // Authorization successful 
                        properties = state.AuthenticationProperties;

                        if (Options.Filter == null || Options.Filter.Invoke(state.WindowsIdentity, Request))
                        {

                            ClaimsIdentity identity;
                            if (Options.OnCreateIdentity == null)
                            {
                                // If the name is something like DOMAIN\username then
                                // grab the name part (and what if it looks like username@domain?)
                                var parts = state.WindowsIdentity.Name.Split(new[] { '\\' }, 2);
                                string shortName = parts.Length == 1 ? parts[0] : parts[parts.Length - 1];

                                // we need to create a new identity using the sign in type that 
                                // the cookie authentication is listening for
                                identity = new ClaimsIdentity(Options.SignInAsAuthenticationType);

                                identity.AddClaims(new[]
                                {
                                    new Claim(ClaimTypes.NameIdentifier, state.WindowsIdentity.User.Value, null,
                                        Options.AuthenticationType),
                                    new Claim(ClaimTypes.Name, shortName),
                                    new Claim(ClaimTypes.Sid, state.WindowsIdentity.User.Value)
                                });
                            }
                            else
                            {
                                identity = Options.OnCreateIdentity(state.WindowsIdentity, Options, Request);
                            }
                            identity.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, NtlmAuthenticationDefaults.AuthenticationType));

                            // We don't need that state anymore
                            Options.LoginStateCache.TryRemove(stateId);

                            // create the authentication ticket
                            Logger.LogInformation("Received valid NTLM Type 3, authentication completed: " + identity.Name);
#if NETFULL
                            return new AuthenticationTicket(identity, properties);
#elif NETCORE2_0
                            var principal = new ClaimsPrincipal(identity);
                            return new AuthenticationTicket(principal, properties, SignInScheme);
#endif
                        }
                    }
                    Logger.LogWarning("Received invalid NTLM Type 3, resending WWW-Authenticate");
                }
                else
                {
                    Logger.LogWarning("No Authorization header received, sending WWW-Authenticate");
                }

                // This code runs under following conditions:
                // - authentication failed (in either step: IsClientResponseValid() or TryAcquireServerChallenge())
                // - there's no token in the headers
                //
                // This means we've got to set the WWW-Authenticate header and return a 401
                Response.Headers.Add("WWW-Authenticate", new[] { "NTLM" });
                Response.StatusCode = 401;
            }

#if NETFULL
            return new AuthenticationTicket(null, properties);
#elif NETCORE2_0
            return null;
#endif
        }

        protected async Task<bool> HandleValidRequestAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.PathBase.Add(Request.Path))
            {
                var ticket = await AuthenticateAsync();
#if NETFULL
                if (ticket?.Identity != null)
#elif NETCORE2_0
                if (ticket?.Principal?.Identity != null && ticket.Principal.Identity.IsAuthenticated)
#endif
                {
#if NETFULL
                    Context.Authentication.SignIn(ticket.Properties, ticket.Identity);
#elif NETCORE2_0
                    await Context.SignInAsync(ticket.Principal.Identity.AuthenticationType, ticket.Principal, ticket.Properties);
#endif
                    Response.Redirect(ticket.Properties.RedirectUri);

                    // Prevent further processing by the owin pipeline.
                    return true;
                }
                if (Response.Headers.ContainsKey("WWW-Authenticate"))
                {
                    return true;
                }
            }

            // Let the rest of the pipeline run
            return false;
        }

        protected void HandleChallenge(AuthenticationProperties properties)
        {
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                throw new ArgumentException("The authentication challenge's redirect URI can't be empty!");
            }

            // get a fairly "unique" string to use in the redirection URL
            var protectedProperties = Options.StateDataFormat.Protect(properties);
            var stateHash = CalculateMD5Hash(protectedProperties);

            // create a new handshake state
            var state = new HandshakeState()
            {
                AuthenticationProperties = properties
            };

            // and store it in the state cache
            Options.LoginStateCache.Add(stateHash, state);

            // redirect to trigger trigger NTLM authentication
#if NETFULL
            var stateUrl = WebUtilities.AddQueryString(Options.CallbackPath.Value, "state", stateHash);
#elif NETCORE2_0
            var stateUrl = QueryHelpers.AddQueryString(Options.CallbackPath.Value, "state", stateHash);
#endif
            Response.Redirect(stateUrl);
        }

#if NETFULL
        /// <summary>
        /// Authenticate the request
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            return await AuthenticateTicketAsync();
        }

        /// <summary>
        /// Apply the first authorization step
        /// </summary>
        /// <returns></returns>
        protected override Task ApplyResponseChallengeAsync()
        {
            // only act on unauthorized responses
            if (Response.StatusCode == 401 && Response.Headers.ContainsKey("WWW-Authenticate") == false)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

                // this migth be our chance to request NTLM authentication!
                if (challenge != null)
                {
                    HandleChallenge(challenge.Properties);
                }
            }

            return Task.Delay(0);
        }

        /// <summary>
        /// This is always invoked on each request. For passive middleware, only do anything if this is
        /// for our callback path when the user is redirected back from the authentication provider.
        /// </summary>
        /// <returns></returns>
        public override async Task<bool> InvokeAsync()
        {
            return await HandleValidRequestAsync();
        }
#endif

#if NETCORE2_0
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var ticket = await AuthenticateTicketAsync();
            if (ticket != null)
            {
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Fail("Failed");
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            // only act on unauthorized responses
            if (Response.StatusCode == 401 && Response.Headers.ContainsKey("WWW-Authenticate") == false)
            {
                HandleChallenge(properties);
            }

            return Task.Delay(0);
        }

        public override async Task<bool> HandleRequestAsync()
        {
            return await HandleValidRequestAsync();
        }

        protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            // Allow login to be constrained to a specific path.
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.PathBase.Add(Request.Path))
            {
                return Task.FromResult(HandleRequestResult.Handle());
            }

            return Task.FromResult(HandleRequestResult.SkipHandler());
        }
#endif

        #region Helpers
        private static readonly MD5 _md5 = MD5.Create();
        public string CalculateMD5Hash(string input)
        {
            // step 1, calculate MD5 hash from input
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);
            byte[] hash = _md5.ComputeHash(inputBytes);

            // step 2, convert byte array to hex string
            var sb = new StringBuilder(hash.Length * 2);
            for (int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("X2"));
            }
            return sb.ToString();
        }
        #endregion
    }
}
