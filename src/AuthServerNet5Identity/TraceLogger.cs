namespace AuthServerNet5Identity
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Text;
    using Microsoft.Framework.Logging;
    using Owin;

    public class TraceLogger : ILogger
    {
        private Func<string, LogLevel, bool> _filter;
        private string name;
        private static readonly Dictionary<LogLevel, string> _logLevelMappings;
        private static readonly string UnknownLogLevel;
        private static readonly int Padding;

        static TraceLogger()
        {
            var dictionary = new Dictionary<LogLevel, string>();
            _logLevelMappings = dictionary;
            UnknownLogLevel = "unknown";
            dictionary.Add( (LogLevel)3, "info" );
            dictionary.Add( (LogLevel)6, "critical" );
            dictionary.Add( (LogLevel)1, "debug" );
            dictionary.Add( (LogLevel)5, "error" );
            dictionary.Add( (LogLevel)2, "verbose" );
            dictionary.Add( (LogLevel)4, "warning" );
            Padding = Math.Max( _logLevelMappings.Values.Max( s => s.Length ), UnknownLogLevel.Length );
        }
        public TraceLogger( string name, Func<string, LogLevel, bool> filter)
        {
            _filter = filter;
            this.name = name;
        }
        public void Log( LogLevel logLevel, int eventId, object state, Exception exception, Func<object, Exception, string> formatter )
        {
            if ( !IsEnabled( logLevel ) )
                return;

            var logValues = state as ILogValues;
            string message = null;
            if ( formatter != null )
                message = formatter( state, exception );
            else if ( logValues != null )
            {
                var builder = new StringBuilder();
                FormatLogValues( builder, logValues, 1, false );
                message = builder.ToString();
                if ( exception != null )
                    message = $"{message}{Environment.NewLine}{exception}";
            }
            else
                message = LogFormatter.Formatter( state, exception );
            if ( string.IsNullOrEmpty( message ) )
                return;

            message = FormatMessage( logLevel, message );

            switch ( logLevel )
            {
            case LogLevel.Debug:
                Trace.WriteLine( message );
                break;
            case LogLevel.Verbose:
                Trace.WriteLine( message );
                break;
            case LogLevel.Information:
                Trace.WriteLine( message );
                break;
            case LogLevel.Warning:
                Trace.TraceWarning( message );
                break;
            case LogLevel.Error:
                Trace.TraceError( message );
                break;
            case LogLevel.Critical:
                Trace.TraceError( message );
                break;
            default:
                throw new ArgumentOutOfRangeException( nameof( logLevel ), logLevel, null );
            }
        }
        public bool IsEnabled( LogLevel logLevel )
        {
            return _filter( name, logLevel );
        }
        public IDisposable BeginScopeImpl( object state )
        {
            return null;
        }

        private string FormatMessage( LogLevel logLevel, string message )
        {
            string str;
            if ( !_logLevelMappings.TryGetValue( logLevel, out str ) )
                str = UnknownLogLevel;
            return $"{str.PadRight( Padding )}: [{name}] {message}";
        }
        private void FormatLogValues( StringBuilder builder, ILogValues logValues, int level, bool bullet )
        {
            IEnumerable<KeyValuePair<string, object>> values = logValues.GetValues();
            if ( values == null )
                return;
            bool flag = true;
            foreach ( KeyValuePair<string, object> keyValuePair in values )
            {
                builder.AppendLine();
                if ( bullet & flag )
                    builder.Append( ' ', level * 2 - 1 ).Append( '-' );
                else
                    builder.Append( ' ', level * 2 );
                builder.Append( keyValuePair.Key ).Append( ": " );
                if ( keyValuePair.Value is IEnumerable && !( keyValuePair.Value is string ) )
                {
                    foreach ( object obj in (IEnumerable)keyValuePair.Value )
                    {
                        if ( obj is ILogValues )
                            this.FormatLogValues( builder, (ILogValues)obj, level + 1, true );
                        else
                            builder.AppendLine().Append( ' ', ( level + 1 ) * 2 ).Append( obj );
                    }
                }
                else if ( keyValuePair.Value is ILogValues )
                    this.FormatLogValues( builder, (ILogValues)keyValuePair.Value, level + 1, false );
                else
                    builder.Append( keyValuePair.Value );
                flag = false;
            }
        }
    }
}