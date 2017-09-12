#if NETFULL
using Microsoft.Owin;
#endif
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Pysco68.Owin.Authentication.Ntlm.Tests
{
    static class Helpers
    {
#if NETFULL
        const string OWIN_CONTEXT = "MS_OwinContext";

        public static OwinContext GetContext(this HttpRequestMessage request)
        {
            if (request.Properties.ContainsKey(OWIN_CONTEXT))
            {
                OwinContext owinContext = request.Properties[OWIN_CONTEXT] as OwinContext;
                return owinContext;
            }

            return null;
        }
#endif

        public static string ReadAsString(this HttpContent content)
        {
#if NETFULL
            return content.ReadAsAsync<string>().Result;
#elif NETCORE
            return content.ReadAsStringAsync().Result;
#endif
        }
    }
}
