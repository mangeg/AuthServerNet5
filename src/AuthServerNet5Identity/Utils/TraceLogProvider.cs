namespace AuthServerNet5Identity
{
    using System;
    using Microsoft.Framework.Logging;

    public class TraceLogProvider : ILoggerProvider
    {
        private Func<string, LogLevel, bool> _filter;

        public TraceLogProvider() {}
        public TraceLogProvider( Func<string, LogLevel, bool> filter )
        {
            _filter = filter;
        }

        public ILogger CreateLogger( string name )
        {
            return new TraceLogger(name, _filter );
        }
    }
}