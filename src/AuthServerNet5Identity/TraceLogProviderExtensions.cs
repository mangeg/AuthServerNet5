namespace AuthServerNet5Identity
{
    using Microsoft.Framework.Logging;

    public static class TraceLogProviderExtensions
    {
        public static void AddTraceLogger( this ILoggerFactory factory )
        {
            factory.AddProvider( new TraceLogProvider() );
        }
        public static void AddTraceLogger( this ILoggerFactory factory, LogLevel minLevel )
        {
            factory.AddProvider( new TraceLogProvider( ( name, level ) => level >= minLevel ) );
        }
    }
}