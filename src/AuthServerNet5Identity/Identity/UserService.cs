namespace AuthServerNet5Identity.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Identity;
    using Thinktecture.IdentityServer.Core.Models;
    using Thinktecture.IdentityServer.Core.Services;
    using Thinktecture.IdentityServer.Core.Extensions;
    using System.Linq;
    using Microsoft.AspNet.Identity.EntityFramework;
    using Microsoft.Framework.DependencyInjection;
    using Thinktecture.IdentityModel;

    public class UserService<TUser, TKey> : IUserService 
        where TUser : IdentityUser<TKey>, new() where TKey : IEquatable<TKey>
    {
        public string DisplayNameClaimType { get; set; }
        public bool EnableSecurityStamp { get; set; }
        protected readonly UserManager<TUser> UserManager;

        public UserService( UserManager<TUser> userManager )
        {
            var use = userManager.FindByNameAsync( "test" ).Result;
            UserManager = userManager;
        }
        public Task<AuthenticateResult> PreAuthenticateAsync( SignInMessage message )
        {
            return Task.FromResult<AuthenticateResult>( null );
        }
        public async Task<AuthenticateResult> AuthenticateLocalAsync( string username, string password, SignInMessage message )
        {
            if ( !UserManager.SupportsUserPassword )
            {
                return null;
            }

            var user = await FindUserAsync( username );
            if ( user == null )
            {
                return null;
            }

            if ( UserManager.SupportsUserLockout &&
                await UserManager.IsLockedOutAsync( user ) )
            {
                return null;
            }

            if ( await UserManager.CheckPasswordAsync( user, password ) )
            {
                if ( UserManager.SupportsUserLockout )
                {
                    await UserManager.ResetAccessFailedCountAsync( user );
                }

                var result = await PostAuthenticateLocalAsync( user, message );
                if ( result != null ) return result;

                var claims = await GetClaimsForAuthenticateResult( user );
                return new AuthenticateResult( user.Id.ToString(), await GetDisplayNameForAccountAsync( user ), claims );
            }
            else if ( UserManager.SupportsUserLockout )
            {
                await UserManager.AccessFailedAsync( user );
            }

            return null;
        }
        public async Task<AuthenticateResult> AuthenticateExternalAsync( ExternalIdentity externalUser, SignInMessage message )
        {
            if ( externalUser == null )
            {
                throw new ArgumentNullException( nameof( externalUser ) );
            }


            //var user = await userManager.FindAsync( new UserLoginInfo( externalUser.Provider, externalUser.ProviderId ) );
            var user = await UserManager.FindByLoginAsync( externalUser.Provider, externalUser.ProviderId );
            if ( user == null )
            {
                return await ProcessNewExternalAccountAsync( externalUser.Provider, externalUser.ProviderId, externalUser.Claims.ToList() );
            }
            else
            {
                return await ProcessExistingExternalAccountAsync( user, externalUser.Provider, externalUser.ProviderId, externalUser.Claims );
            }
        }
        public Task SignOutAsync( ClaimsPrincipal subject )
        {
            return Task.FromResult<object>( null );
        }
        public async Task<IEnumerable<Claim>> GetProfileDataAsync( ClaimsPrincipal subject, IEnumerable<string> requestedClaimTypes = null )
        {
            if ( subject == null ) throw new ArgumentNullException( nameof( subject ) );

            var acct = await UserManager.FindByIdAsync( subject.GetSubjectId() );
            if ( acct == null )
            {
                throw new ArgumentException( "Invalid subject identifier" );
            }

            var claims = await GetClaimsFromAccount( acct );
            if ( requestedClaimTypes != null )
            {
                var requestClaimTypesList = requestedClaimTypes.ToList();
                if ( requestClaimTypesList.Any() )
                {
                    claims = claims.Where( x => requestClaimTypesList.Contains( x.Type ) );
                }
            }
            return claims;
        }
        public async Task<bool> IsActiveAsync( ClaimsPrincipal subject )
        {
            if ( subject == null ) throw new ArgumentNullException( nameof( subject ) );

            var id = subject.GetSubjectId();
            var acct = await UserManager.FindByIdAsync( id );
            if ( acct == null )
            {
                return false;
            }

            if ( EnableSecurityStamp && UserManager.SupportsUserSecurityStamp )
            {
                var securityStamp = subject.Claims.Where( x => x.Type == "security_stamp" ).Select( x => x.Value ).SingleOrDefault();
                if ( securityStamp != null )
                {
                    var dbSecurityStamp = await UserManager.GetSecurityStampAsync( acct );
                    if ( dbSecurityStamp != securityStamp )
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        //////////////////////////
        protected async virtual Task<TUser> FindUserAsync( string username )
        {
            return await UserManager.FindByNameAsync( username );
        }

        protected virtual Task<AuthenticateResult> PostAuthenticateLocalAsync( TUser account, SignInMessage message )
        {
            return Task.FromResult<AuthenticateResult>( null );
        }

        protected virtual async Task<IEnumerable<Claim>> GetClaimsForAuthenticateResult( TUser user )
        {
            var claims = new List<Claim>();
            if ( EnableSecurityStamp && UserManager.SupportsUserSecurityStamp )
            {
                var stamp = await UserManager.GetSecurityStampAsync( user );
                if ( !string.IsNullOrWhiteSpace( stamp ) )
                {
                    claims.Add( new Claim( "security_stamp", stamp ) );
                }
            }
            return claims;
        }

        protected virtual async Task<string> GetDisplayNameForAccountAsync( TUser user )
        {
            var claims = ( await GetClaimsFromAccount( user ) ).ToList();

            Claim nameClaim = null;
            if ( DisplayNameClaimType != null )
            {
                nameClaim = claims.FirstOrDefault( x => x.Type == DisplayNameClaimType );
            }
            if ( nameClaim == null ) nameClaim = claims.FirstOrDefault( x => x.Type == Thinktecture.IdentityServer.Core.Constants.ClaimTypes.Name );
            if ( nameClaim == null ) nameClaim = claims.FirstOrDefault( x => x.Type == ClaimTypes.Name );
            if ( nameClaim != null ) return nameClaim.Value;

            return user.UserName;
        }

        protected virtual async Task<IEnumerable<Claim>> GetClaimsFromAccount( TUser user )
        {
            var claims = new List<Claim>{
                new Claim(Thinktecture.IdentityServer.Core.Constants.ClaimTypes.Subject, user.Id.ToString()),
                new Claim(Thinktecture.IdentityServer.Core.Constants.ClaimTypes.PreferredUserName, user.UserName),
            };

            if ( UserManager.SupportsUserEmail )
            {
                var email = await UserManager.GetEmailAsync( user );
                if ( !string.IsNullOrWhiteSpace( email ) )
                {
                    claims.Add( new Claim( Thinktecture.IdentityServer.Core.Constants.ClaimTypes.Email, email ) );
                    var verified = await UserManager.IsEmailConfirmedAsync( user );
                    claims.Add( new Claim( Thinktecture.IdentityServer.Core.Constants.ClaimTypes.EmailVerified, verified ? "true" : "false" ) );
                }
            }

            if ( UserManager.SupportsUserPhoneNumber )
            {
                var phone = await UserManager.GetPhoneNumberAsync( user );
                if ( !string.IsNullOrWhiteSpace( phone ) )
                {
                    claims.Add( new Claim( Thinktecture.IdentityServer.Core.Constants.ClaimTypes.PhoneNumber, phone ) );
                    var verified = await UserManager.IsPhoneNumberConfirmedAsync( user );
                    claims.Add( new Claim( Thinktecture.IdentityServer.Core.Constants.ClaimTypes.PhoneNumberVerified, verified ? "true" : "false" ) );
                }
            }

            if ( UserManager.SupportsUserClaim )
            {
                claims.AddRange( await UserManager.GetClaimsAsync( user ) );
            }

            if ( UserManager.SupportsUserRole )
            {
                var roleClaims =
                    from role in await UserManager.GetRolesAsync( user )
                    select new Claim( Thinktecture.IdentityServer.Core.Constants.ClaimTypes.Role, role );
                claims.AddRange( roleClaims );
            }

            return claims;
        }

        protected virtual async Task<AuthenticateResult> ProcessNewExternalAccountAsync( string provider, string providerId, IList<Claim> claims )
        {
            var user = await InstantiateNewUserFromExternalProviderAsync( provider, providerId, claims );
            if ( user == null ) throw new InvalidOperationException( "CreateNewAccountFromExternalProvider returned null" );

            var createResult = await UserManager.CreateAsync( user );
            if ( !createResult.Succeeded )
            {
                return new AuthenticateResult( createResult.Errors.First().Description );
            }

            var externalLogin = new UserLoginInfo( provider, providerId, "" );
            var addExternalResult = await UserManager.AddLoginAsync( user, externalLogin );
            if ( !addExternalResult.Succeeded )
            {
                return new AuthenticateResult( addExternalResult.Errors.First().Description );
            }

            var result = await AccountCreatedFromExternalProviderAsync( user, provider, providerId, claims );
            if ( result != null ) return result;

            return await SignInFromExternalProviderAsync( user, provider );
        }

        protected virtual Task<TUser> InstantiateNewUserFromExternalProviderAsync( string provider, string providerId, IEnumerable<Claim> claims )
        {
            var user = new TUser { UserName = Guid.NewGuid().ToString( "N" ) };
            return Task.FromResult( user );
        }

        protected virtual async Task<AuthenticateResult> AccountCreatedFromExternalProviderAsync( TUser user, string provider, string providerId, IList<Claim> claims )
        {
            claims = ( await SetAccountEmailAsync( user, claims ) ).ToList();
            claims = ( await SetAccountPhoneAsync( user, claims ) ).ToList();

            return await UpdateAccountFromExternalClaimsAsync( user, provider, providerId, claims );
        }

        protected virtual async Task<AuthenticateResult> UpdateAccountFromExternalClaimsAsync( TUser user, string provider, string providerId, IList<Claim> claims )
        {
            var existingClaims = await UserManager.GetClaimsAsync( user );
            var intersection = existingClaims.Intersect( claims, new ClaimComparer() );
            var newClaims = claims.Except( intersection, new ClaimComparer() );

            foreach ( var claim in newClaims )
            {
                var result = await UserManager.AddClaimAsync( user, claim );
                if ( !result.Succeeded )
                {
                    return new AuthenticateResult( result.Errors.First().Description );
                }
            }

            return null;
        }

        protected virtual async Task<IEnumerable<Claim>> SetAccountEmailAsync( TUser user, IList<Claim> claims )
        {
            var email = claims.FirstOrDefault( x => x.Type == Thinktecture.IdentityServer.Core.Constants.ClaimTypes.Email );
            if ( email != null )
            {
                var userEmail = await UserManager.GetEmailAsync( user );
                if ( userEmail == null )
                {
                    // if this fails, then presumably the email is already associated with another account
                    // so ignore the error and let the claim pass thru
                    var result = await UserManager.SetEmailAsync( user, email.Value );
                    if ( result.Succeeded )
                    {
                        var emailVerified = claims.FirstOrDefault( x => x.Type == Thinktecture.IdentityServer.Core.Constants.ClaimTypes.EmailVerified );
                        if ( emailVerified != null && emailVerified.Value == "true" )
                        {
                            var token = await UserManager.GenerateEmailConfirmationTokenAsync( user );
                            await UserManager.ConfirmEmailAsync( user, token );
                        }

                        var emailClaims = new[] { Thinktecture.IdentityServer.Core.Constants.ClaimTypes.Email, Thinktecture.IdentityServer.Core.Constants.ClaimTypes.EmailVerified };
                        return claims.Where( x => !emailClaims.Contains( x.Type ) );
                    }
                }
            }

            return claims;
        }

        protected virtual async Task<IEnumerable<Claim>> SetAccountPhoneAsync( TUser user, IList<Claim> claims )
        {
            var phone = claims.FirstOrDefault( x => x.Type == Thinktecture.IdentityServer.Core.Constants.ClaimTypes.PhoneNumber );
            if ( phone != null )
            {
                var userPhone = await UserManager.GetPhoneNumberAsync( user );
                if ( userPhone == null )
                {
                    // if this fails, then presumably the phone is already associated with another account
                    // so ignore the error and let the claim pass thru
                    var result = await UserManager.SetPhoneNumberAsync( user, phone.Value );
                    if ( result.Succeeded )
                    {
                        var phoneVerified = claims.FirstOrDefault( x => x.Type == Thinktecture.IdentityServer.Core.Constants.ClaimTypes.PhoneNumberVerified );
                        if ( phoneVerified != null && phoneVerified.Value == "true" )
                        {
                            var token = await UserManager.GenerateChangePhoneNumberTokenAsync( user, phone.Value );
                            await UserManager.ChangePhoneNumberAsync( user, phone.Value, token );
                        }

                        var phoneClaims = new[] { Thinktecture.IdentityServer.Core.Constants.ClaimTypes.PhoneNumber, Thinktecture.IdentityServer.Core.Constants.ClaimTypes.PhoneNumberVerified };
                        return claims.Where( x => !phoneClaims.Contains( x.Type ) );
                    }
                }
            }

            return claims;
        }

        protected virtual async Task<AuthenticateResult> SignInFromExternalProviderAsync( TUser user, string provider )
        {
            var claims = await GetClaimsForAuthenticateResult( user );

            return new AuthenticateResult(
                user.Id.ToString(),
                await GetDisplayNameForAccountAsync( user ),
                claims,
                authenticationMethod: Thinktecture.IdentityServer.Core.Constants.AuthenticationMethods.External,
                identityProvider: provider );
        }

        protected virtual async Task<AuthenticateResult> ProcessExistingExternalAccountAsync( TUser user, string provider, string providerId, IEnumerable<Claim> claims )
        {
            return await SignInFromExternalProviderAsync( user, provider );
        }
    }
}
