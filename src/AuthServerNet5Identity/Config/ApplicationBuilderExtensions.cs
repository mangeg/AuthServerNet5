namespace AuthServerNet5Identity.Config
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Builder;
    using Microsoft.AspNet.DataProtection;
    using Microsoft.Framework.DependencyInjection;
    using Microsoft.Owin.Builder;
    using Owin;
    using Thinktecture.IdentityManager.Configuration;
    using Thinktecture.IdentityServer.Core.Configuration;

    using DataProtectionProviderDelegate = System.Func<string[], System.Tuple<System.Func<byte[], byte[]>, System.Func<byte[], byte[]>>>;
    using DataProtectionTuple = System.Tuple<System.Func<byte[], byte[]>, System.Func<byte[], byte[]>>;

    public static class ApplicationBuilderExtensions
    {
        public static void UseIdentityServer( this IApplicationBuilder app, IdentityServerOptions options )
        {
            app.UseOwin(
                addToPipeline => {
                    addToPipeline(
                        next => {
                            var builder = new AppBuilder();

                            var provider = app.ApplicationServices.GetService<IDataProtectionProvider>();
                            builder.Properties["security.DataProtectionProvider"] = new DataProtectionProviderDelegate(
                                purposes => {
                                    var dataProtection = provider.CreateProtector( string.Join( ",", purposes ) );
                                    return new DataProtectionTuple( dataProtection.Protect, dataProtection.Unprotect );
                                } );


                            builder.UseIdentityServer( options );

                            var appFunc =
                                builder.Build( typeof(Func<IDictionary<string, object>, Task>) ) as
                                    Func<IDictionary<string, object>, Task>;

                            return appFunc;
                        } );
                } );
        }

        public static void UseIdentityManager( this IApplicationBuilder app, IdentityManagerOptions options )
        {
            app.UseOwin(
                addToPipeline =>
                {
                    addToPipeline(
                        next =>
                        {
                            var builder = new AppBuilder();

                            builder.UseIdentityManager( options );

                            var appFunc =
                                 builder.Build( typeof( Func<IDictionary<string, object>, Task> ) ) as
                                     Func<IDictionary<string, object>, Task>;

                            return appFunc;
                        } );
                }
                );
        }
    }
}