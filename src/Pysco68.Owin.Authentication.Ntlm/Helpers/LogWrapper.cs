#if NETFULL
using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Owin.Logging;

namespace Pysco68.Owin.Authentication.Ntlm.Helpers
{
    class LogWrapper
    {
        private readonly ILogger _logger;

        public LogWrapper(ILogger logger)
        {
            _logger = logger;
        }

        public void LogCritical(string message)
        {
            _logger.WriteCritical(message);
        }

        public void LogError(string message)
        {
            _logger.WriteError(message);
        }

        public void LogInformation(string message)
        {
            _logger.WriteInformation(message);
        }

        public void LogVerbose(string message)
        {
            _logger.WriteVerbose(message);
        }

        public void LogWarning(string message)
        {
            _logger.WriteWarning(message);
        }
    }
}
#endif
