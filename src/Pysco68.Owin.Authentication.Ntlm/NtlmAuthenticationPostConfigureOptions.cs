#if NETCORE2_0
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace Pysco68.Owin.Authentication.Ntlm
{
    class NtlmAuthenticationPostConfigureOptions<TOptions, THandler> : IPostConfigureOptions<TOptions>
        where TOptions : NtlmAuthenticationOptions, new()
        where THandler : NtlmAuthenticationHandler<TOptions>
    {
        private readonly IDataProtectionProvider _dataProtection;

        public NtlmAuthenticationPostConfigureOptions(IDataProtectionProvider dataProtection)
        {
            _dataProtection = dataProtection;
        }

        public void PostConfigure(string name, TOptions options)
        {
            if (options.StateDataFormat == null)
            {
                var type = typeof(THandler);
                var typeName = type.FullName;
                var dataProtector =
                    _dataProtection.CreateProtector(typeName, NtlmAuthenticationDefaults.AuthenticationType);
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
        }
    }
}
#endif
