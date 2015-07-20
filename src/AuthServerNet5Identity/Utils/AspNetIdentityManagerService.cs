namespace AuthServerNet5Identity.Config
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.EntityFramework;
    using Microsoft.Framework.OptionsModel;
    using Thinktecture.IdentityManager;

    public class AspNetIdentityManagerService<TUser, TUserKey, TRole, TRoleKey> : IIdentityManagerService
        where TUser : IdentityUser<TUserKey>, new()
        where TUserKey: IEquatable<TUserKey>
        where TRole : IdentityRole<TRoleKey>, new()
        where TRoleKey : IEquatable<TRoleKey>
    {
        private readonly IOptions<IdentityOptions> _userOptions;
        public string RoleClaimType { get; set; }
        private readonly UserManager<TUser> _userManager;
        private readonly RoleManager<TRole> _roleManager;
        private readonly Func<Task<IdentityManagerMetadata>> _metadataFunc;

        private AspNetIdentityManagerService(
            UserManager<TUser> userMgr,
            RoleManager<TRole> roleMgr )
        {
            if ( userMgr == null ) throw new ArgumentNullException( nameof( userMgr ) );
            if ( roleMgr == null ) throw new ArgumentNullException( nameof( roleMgr ) );

            _userManager = userMgr;
            _roleManager = roleMgr;

            if ( !_userManager.SupportsQueryableUsers )
            {
                throw new InvalidOperationException( "UserManager must support queryable users." );
            }

            /*if ( userManager.UserTokenProvider == null )
            {
                userManager.UserTokenProvider = new TokenProvider<TUser, TUserKey>();
            }*/

            RoleClaimType = Constants.ClaimTypes.Role;
        }

        public AspNetIdentityManagerService(
            UserManager<TUser> userManager,
            RoleManager<TRole> roleManager,
            IOptions<IdentityOptions> userOptions,
            bool includeAccountProperties = true )
            : this( userManager, roleManager )
        {
            _userOptions = userOptions;
            _metadataFunc = () => Task.FromResult( GetStandardMetadata( includeAccountProperties ) );
        }

        public AspNetIdentityManagerService(
            UserManager<TUser> userManager,
            RoleManager<TRole> roleManager,
            IdentityManagerMetadata metadata )
            : this( userManager, roleManager, () => Task.FromResult( metadata ) )
        {
        }

        public AspNetIdentityManagerService(
            UserManager<TUser> userManager,
            RoleManager<TRole> roleManager,
            Func<Task<IdentityManagerMetadata>> metadataFunc )
            : this( userManager, roleManager )
        {
            _metadataFunc = metadataFunc;
        }

        public Task<IdentityManagerMetadata> GetMetadataAsync()
        {
            return _metadataFunc();
        }
        public async Task<IdentityManagerResult<CreateResult>> CreateUserAsync( IEnumerable<PropertyValue> properties )
        {
            var propertyValues = properties as PropertyValue[] ?? properties.ToArray();
            var usernameClaim = propertyValues.Single( x => x.Type == Constants.ClaimTypes.Username );
            var passwordClaim = propertyValues.Single( x => x.Type == Constants.ClaimTypes.Password );

            var username = usernameClaim.Value;
            var password = passwordClaim.Value;

            var exclude = new[] { Constants.ClaimTypes.Username, Constants.ClaimTypes.Password };
            var otherProperties = propertyValues.Where( x => !exclude.Contains( x.Type ) ).ToArray();

            var metadata = await GetMetadataAsync();
            var createProps = metadata.UserMetadata.GetCreateProperties().ToList();

            var user = new TUser { UserName = username };
            foreach ( var prop in otherProperties )
            {
                var propertyResult = SetUserProperty( createProps, user, prop.Type, prop.Value );
                if ( !propertyResult.IsSuccess )
                {
                    return new IdentityManagerResult<CreateResult>( propertyResult.Errors.ToArray() );
                }
            }

            var result = await _userManager.CreateAsync( user, password );
            if ( !result.Succeeded )
            {
                return new IdentityManagerResult<CreateResult>( result.Errors.Select( e => e.Description ).ToArray() );
            }

            return new IdentityManagerResult<CreateResult>( new CreateResult { Subject = user.Id.ToString() } );
        }
        public async Task<IdentityManagerResult> DeleteUserAsync( string subject )
        {
            var user = await _userManager.FindByIdAsync( subject );
            if ( user == null )
            {
                return new IdentityManagerResult( "Invalid subject" );
            }

            var result = await _userManager.DeleteAsync( user );
            if ( !result.Succeeded )
            {
                return new IdentityManagerResult<CreateResult>( result.Errors.Select( e => e.Description ).ToArray() );
            }

            return IdentityManagerResult.Success;
        }
        public async Task<IdentityManagerResult<QueryResult<UserSummary>>> QueryUsersAsync( string filter, int start, int count )
        {
            var query =
                from user in _userManager.Users
                orderby user.UserName
                select user;

            if ( !string.IsNullOrWhiteSpace( filter ) )
            {
                query =
                    from user in query
                    where user.UserName.Contains( filter )
                    orderby user.UserName
                    select user;
            }

            int total = query.Count();
            var users = query.Skip( start ).Take( count ).ToArray();

            var result = new QueryResult<UserSummary>
            {
                Start = start,
                Count = count,
                Total = total,
                Filter = filter
            };
            var tempItems = new List<UserSummary>();
            foreach ( var x in users )
            {
                var user = new UserSummary
                {
                    Subject = x.Id.ToString(),
                    Username = x.UserName,
                    Name = await DisplayNameFromUser( x )
                };
                tempItems.Add( user );
            }
            result.Items = tempItems;

            return new IdentityManagerResult<QueryResult<UserSummary>>( result );
        }
        public async Task<IdentityManagerResult<UserDetail>> GetUserAsync( string subject )
        {
            var user = await _userManager.FindByIdAsync( subject );
            if ( user == null )
            {
                return new IdentityManagerResult<UserDetail>( (UserDetail)null );
            }

            var result = new UserDetail
            {
                Subject = subject,
                Username = user.UserName,
                Name = await DisplayNameFromUser( user ),
            };

            var metadata = await GetMetadataAsync();

            var props =
                from prop in metadata.UserMetadata.UpdateProperties
                select new PropertyValue
                {
                    Type = prop.Type,
                    Value = GetUserProperty( prop, user )
                };
            result.Properties = props.ToArray();

            if ( _userManager.SupportsUserClaim )
            {
                var userClaims = await _userManager.GetClaimsAsync( user );
                var claims = new List<ClaimValue>();
                if ( userClaims != null )
                {
                    claims.AddRange( userClaims.Select( x => new ClaimValue { Type = x.Type, Value = x.Value } ) );
                }
                result.Claims = claims.ToArray();
            }

            return new IdentityManagerResult<UserDetail>( result );
        }
        public async Task<IdentityManagerResult> SetUserPropertyAsync( string subject, string type, string value )
        {
            var user = await _userManager.FindByIdAsync( subject );
            if ( user == null )
            {
                return new IdentityManagerResult( "Invalid subject" );
            }

            var errors = ValidateUserProperty( type, value ).ToList();
            if ( errors.Any() )
            {
                return new IdentityManagerResult( errors.ToArray() );
            }

            var metadata = await GetMetadataAsync();
            var propResult = SetUserProperty( metadata.UserMetadata.UpdateProperties, user, type, value );
            if ( !propResult.IsSuccess )
            {
                return propResult;
            }

            var result = await _userManager.UpdateAsync( user );
            if ( !result.Succeeded )
            {
                return new IdentityManagerResult( result.Errors.Select( e => e.Description ).ToArray() );
            }

            return IdentityManagerResult.Success;
        }
        public async Task<IdentityManagerResult> AddUserClaimAsync( string subject, string type, string value )
        {
            var user = await _userManager.FindByIdAsync( subject );
            if ( user == null )
            {
                return new IdentityManagerResult( "Invalid subject" );
            }

            var existingClaims = await _userManager.GetClaimsAsync( user );
            if ( !existingClaims.Any( x => x.Type == type && x.Value == value ) )
            {
                var result = await _userManager.AddClaimAsync( user, new System.Security.Claims.Claim( type, value ) );
                if ( !result.Succeeded )
                {
                    return new IdentityManagerResult<CreateResult>( result.Errors.Select( e => e.Description ).ToArray() );
                }
            }

            return IdentityManagerResult.Success;
        }
        public async Task<IdentityManagerResult> RemoveUserClaimAsync( string subject, string type, string value )
        {
            var user = await _userManager.FindByIdAsync( subject );
            if ( user == null )
            {
                return new IdentityManagerResult( "Invalid subject" );
            }

            var result = await _userManager.RemoveClaimAsync( user, new System.Security.Claims.Claim( type, value ) );
            if ( !result.Succeeded )
            {
                return new IdentityManagerResult<CreateResult>( result.Errors.Select( e => e.Description ).ToArray() );
            }

            return IdentityManagerResult.Success;
        }
        public async Task<IdentityManagerResult<CreateResult>> CreateRoleAsync( IEnumerable<PropertyValue> properties )
        {
            ValidateSupportsRoles();

            var propertyValues = properties as PropertyValue[] ?? properties.ToArray();
            var nameClaim = propertyValues.Single( x => x.Type == Constants.ClaimTypes.Name );

            var name = nameClaim.Value;

            string[] exclude = { Constants.ClaimTypes.Name };
            var otherProperties = propertyValues.Where( x => !exclude.Contains( x.Type ) ).ToArray();

            var metadata = await GetMetadataAsync();
            var createProps = metadata.RoleMetadata.GetCreateProperties().ToList();

            TRole role = new TRole() { Name = name };
            foreach ( var prop in otherProperties )
            {
                var roleResult = SetRoleProperty( createProps, role, prop.Type, prop.Value );
                if ( !roleResult.IsSuccess )
                {
                    return new IdentityManagerResult<CreateResult>( roleResult.Errors.ToArray() );
                }
            }

            var result = await _roleManager.CreateAsync( role );
            if ( !result.Succeeded )
            {
                return new IdentityManagerResult<CreateResult>( result.Errors.Select( e => e.Description ).ToArray() );
            }

            return new IdentityManagerResult<CreateResult>( new CreateResult { Subject = role.Id.ToString() } );
        }
        public async Task<IdentityManagerResult> DeleteRoleAsync( string subject )
        {
            ValidateSupportsRoles();

            var role = await _roleManager.FindByIdAsync( subject );
            if ( role == null )
            {
                return new IdentityManagerResult( "Invalid subject" );
            }

            var result = await _roleManager.DeleteAsync( role );
            if ( !result.Succeeded )
            {
                return new IdentityManagerResult<CreateResult>( result.Errors.Select( e => e.Description ).ToArray() );
            }

            return IdentityManagerResult.Success;
        }
        public Task<IdentityManagerResult<QueryResult<RoleSummary>>> QueryRolesAsync( string filter, int start, int count )
        {
            ValidateSupportsRoles();

            if ( start < 0 ) start = 0;
            if ( count < 0 ) count = Int32.MaxValue;

            var query =
                from role in _roleManager.Roles
                orderby role.Name
                select role;

            if ( !String.IsNullOrWhiteSpace( filter ) )
            {
                query =
                    from role in query
                    where role.Name.Contains( filter )
                    orderby role.Name
                    select role;
            }

            int total = query.Count();
            var roles = query.Skip( start ).Take( count ).ToArray();

            var result = new QueryResult<RoleSummary>
            {
                Start = start,
                Count = count,
                Total = total,
                Filter = filter,
                Items = roles.Select(
                    x => {
                        var user = new RoleSummary
                        {
                            Subject = x.Id.ToString(),
                            Name = x.Name
                            // Description
                        };

                        return user;
                    } ).ToArray()
            };

            return Task.FromResult( new IdentityManagerResult<QueryResult<RoleSummary>>( result ) );
        }
        public async Task<IdentityManagerResult<RoleDetail>> GetRoleAsync( string subject )
        {
            ValidateSupportsRoles();

            var role = await _roleManager.FindByIdAsync( subject );
            if ( role == null )
            {
                return new IdentityManagerResult<RoleDetail>( (RoleDetail)null );
            }

            var result = new RoleDetail
            {
                Subject = subject,
                Name = role.Name,
                // Description
            };

            var metadata = await GetMetadataAsync();

            var props =
                from prop in metadata.RoleMetadata.UpdateProperties
                select new PropertyValue
                {
                    Type = prop.Type,
                    Value = GetRoleProperty( prop, role )
                };
            result.Properties = props.ToArray();

            return new IdentityManagerResult<RoleDetail>( result );
        }
        public async Task<IdentityManagerResult> SetRolePropertyAsync( string subject, string type, string value )
        {
            ValidateSupportsRoles();

            var role = await _roleManager.FindByIdAsync( subject );
            if ( role == null )
            {
                return new IdentityManagerResult( "Invalid subject" );
            }

            var errors = ValidateRoleProperty( type, value ).ToList();
            if ( errors.Any() )
            {
                return new IdentityManagerResult( errors.ToArray() );
            }

            var metadata = await GetMetadataAsync();
            var result = SetRoleProperty( metadata.RoleMetadata.UpdateProperties, role, type, value );
            if ( !result.IsSuccess )
            {
                return result;
            }

            var updateResult = await _roleManager.UpdateAsync( role );
            if ( !updateResult.Succeeded )
            {
                return new IdentityManagerResult( result.Errors.ToArray() );
            }

            return IdentityManagerResult.Success;
        }

        public virtual IdentityManagerMetadata GetStandardMetadata( bool includeAccountProperties = true )
        {
            var update = new List<PropertyMetadata>();
            if ( _userManager.SupportsUserPassword )
            {
                update.Add(
                    PropertyMetadata.FromFunctions<TUser, string>(
                        Constants.ClaimTypes.Password,
                        x => null,
                        SetPassword,
                        name: "Password",
                        dataType: PropertyDataType.Password,
                        required: true ) );
            }
            if ( _userManager.SupportsUserEmail )
            {
                update.Add(
                    PropertyMetadata.FromFunctions<TUser, string>(
                        Constants.ClaimTypes.Email,
                        GetEmail,
                        SetEmail,
                        name: "Email",
                        dataType: PropertyDataType.Email ) );
            }
            if ( _userManager.SupportsUserPhoneNumber )
            {
                update.Add(
                    PropertyMetadata.FromFunctions<TUser, string>(
                        Constants.ClaimTypes.Phone,
                        GetPhone,
                        SetPhone,
                        name: "Phone",
                        dataType: PropertyDataType.String ) );
            }
            if ( _userManager.SupportsUserTwoFactor )
            {
                update.Add(
                    PropertyMetadata.FromFunctions<TUser, bool>(
                        "two_factor",
                        GetTwoFactorEnabled,
                        SetTwoFactorEnabled,
                        name: "Two Factor Enabled",
                        dataType: PropertyDataType.Boolean ) );
            }
            if ( _userManager.SupportsUserLockout )
            {
                update.Add(
                    PropertyMetadata.FromFunctions<TUser, bool>(
                        "locked_enabled",
                        GetLockoutEnabled,
                        SetLockoutEnabled,
                        name: "Lockout Enabled",
                        dataType: PropertyDataType.Boolean ) );
                update.Add(
                    PropertyMetadata.FromFunctions<TUser, bool>(
                        "locked",
                        GetLockedOut,
                        SetLockedOut,
                        name: "Locked Out",
                        dataType: PropertyDataType.Boolean ) );
            }

            if ( includeAccountProperties )
            {
                update.AddRange( PropertyMetadata.FromType<TUser>( new string[] { } ) );
            }

            var create = new List<PropertyMetadata>
            {
                PropertyMetadata.FromProperty<TUser>( x => x.UserName, type: Constants.ClaimTypes.Username, required: true ),
                PropertyMetadata.FromFunctions<TUser, string>(
                    Constants.ClaimTypes.Password,
                    x => null,
                    SetPassword,
                    name: "Password",
                    dataType: PropertyDataType.Password,
                    required: true )
            };
            if ( _userOptions.Options.User.RequireUniqueEmail )
            {
                create.Add( PropertyMetadata.FromProperty<TUser>( x => x.Email, type: Constants.ClaimTypes.Email, required: true ) );
            }

            var user = new UserMetadata
            {
                SupportsCreate = true,
                SupportsDelete = true,
                SupportsClaims = _userManager.SupportsUserClaim,
                CreateProperties = create,
                UpdateProperties = update
            };

            var role = new RoleMetadata
            {
                RoleClaimType = RoleClaimType,
                SupportsCreate = true,
                SupportsDelete = true,
                CreateProperties = new[]
                {
                    PropertyMetadata.FromProperty<TRole>( x => x.Name, type: Constants.ClaimTypes.Name, required: true )
                },
                UpdateProperties = PropertyMetadata.FromType<TRole>( new string[] { } )
            };

            var meta = new IdentityManagerMetadata
            {
                UserMetadata = user,
                RoleMetadata = role
            };
            return meta;
        }

        protected virtual async Task<string> DisplayNameFromUser( TUser user )
        {
            if ( _userManager.SupportsUserClaim )
            {
                var claims = await _userManager.GetClaimsAsync( user );
                var name = claims.Where( x => x.Type == Constants.ClaimTypes.Name ).Select( x => x.Value ).FirstOrDefault();
                if ( !string.IsNullOrWhiteSpace( name ) )
                {
                    return name;
                }
            }
            return null;
        }

        protected virtual IdentityManagerResult SetUserProperty(
            IEnumerable<PropertyMetadata> propsMeta,
            TUser user,
            string type,
            string value )
        {
            IdentityManagerResult result;
            if ( propsMeta.TrySet( user, type, value, out result ) )
            {
                return result;
            }

            throw new Exception( "Invalid property type " + type );
        }
        protected virtual string GetUserProperty( PropertyMetadata propMetadata, TUser user )
        {
            string val;
            if ( propMetadata.TryGet( user, out val ) )
            {
                return val;
            }

            throw new Exception( "Invalid property type " + propMetadata.Type );
        }

        protected virtual IdentityManagerResult SetRoleProperty(
            IEnumerable<PropertyMetadata> propsMeta,
            TRole role,
            string type,
            string value )
        {
            IdentityManagerResult result;
            if ( propsMeta.TrySet( role, type, value, out result ) )
            {
                return result;
            }

            throw new Exception( "Invalid property type " + type );
        }
        protected virtual string GetRoleProperty( PropertyMetadata propMetadata, TRole role )
        {
            string val;
            if ( propMetadata.TryGet( role, out val ) )
            {
                return val;
            }

            throw new Exception( "Invalid property type " + propMetadata.Type );
        }

        public virtual IdentityManagerResult SetPassword( TUser user, string password )
        {
            var token = _userManager.GeneratePasswordResetTokenAsync( user ).Result;
            var result = _userManager.ResetPasswordAsync( user, token, password ).Result;
            if ( !result.Succeeded )
            {
                return new IdentityManagerResult( result.Errors.First().Description );
            }
            return IdentityManagerResult.Success;
        }

        public virtual string GetEmail( TUser user )
        {
            return _userManager.GetEmailAsync( user ).Result;
        }
        public virtual IdentityManagerResult SetEmail( TUser user, string email )
        {
            var result = _userManager.SetEmailAsync( user, email ).Result;
            if ( !result.Succeeded )
            {
                return new IdentityManagerResult( result.Errors.First().Description );
            }

            if ( !String.IsNullOrWhiteSpace( email ) )
            {
                var token = _userManager.GenerateEmailConfirmationTokenAsync( user ).Result;
                result = _userManager.ConfirmEmailAsync( user, token ).Result;
                if ( !result.Succeeded )
                {
                    return new IdentityManagerResult( result.Errors.First().Description );
                }
            }

            return IdentityManagerResult.Success;
        }

        public virtual string GetPhone( TUser user )
        {
            return _userManager.GetPhoneNumberAsync( user ).Result;
        }
        public virtual IdentityManagerResult SetPhone( TUser user, string phone )
        {
            var result = _userManager.SetPhoneNumberAsync( user, phone ).Result;
            if ( !result.Succeeded )
            {
                return new IdentityManagerResult( result.Errors.First().Description );
            }

            if ( !String.IsNullOrWhiteSpace( phone ) )
            {
                var token = _userManager.GenerateChangePhoneNumberTokenAsync( user, phone ).Result;
                result = _userManager.ChangePhoneNumberAsync( user, phone, token ).Result;
                if ( !result.Succeeded )
                {
                    return new IdentityManagerResult( result.Errors.First().Description );
                }
            }

            return IdentityManagerResult.Success;
        }

        public virtual bool GetTwoFactorEnabled( TUser user )
        {
            return _userManager.GetTwoFactorEnabledAsync( user ).Result;
        }
        public virtual IdentityManagerResult SetTwoFactorEnabled( TUser user, bool enabled )
        {
            var result = _userManager.SetTwoFactorEnabledAsync( user, enabled ).Result;
            if ( !result.Succeeded )
            {
                return new IdentityManagerResult( result.Errors.First().Description );
            }

            return IdentityManagerResult.Success;
        }

        public virtual bool GetLockoutEnabled( TUser user )
        {
            return _userManager.GetLockoutEnabledAsync( user ).Result;
        }
        public virtual IdentityManagerResult SetLockoutEnabled( TUser user, bool enabled )
        {
            var result = _userManager.SetLockoutEnabledAsync( user, enabled ).Result;
            if ( !result.Succeeded )
            {
                return new IdentityManagerResult( result.Errors.First().Description );
            }

            return IdentityManagerResult.Success;
        }

        public virtual bool GetLockedOut( TUser user )
        {
            return _userManager.GetLockoutEndDateAsync( user ).Result > DateTimeOffset.UtcNow;
        }
        public virtual IdentityManagerResult SetLockedOut( TUser user, bool locked )
        {
            if ( locked )
            {
                var result = _userManager.SetLockoutEndDateAsync( user, DateTimeOffset.MaxValue ).Result;
                if ( !result.Succeeded )
                {
                    return new IdentityManagerResult( result.Errors.First().Description );
                }
            }
            else
            {
                var result = _userManager.SetLockoutEndDateAsync( user, DateTimeOffset.MinValue ).Result;
                if ( !result.Succeeded )
                {
                    return new IdentityManagerResult( result.Errors.First().Description );
                }
            }

            return IdentityManagerResult.Success;
        }

        protected virtual IEnumerable<string> ValidateUserProperty( string type, string value )
        {
            return Enumerable.Empty<string>();
        }
        protected virtual void ValidateSupportsRoles()
        {
            if ( _roleManager == null )
            {
                throw new InvalidOperationException( "Roles Not Supported" );
            }
        }
        protected virtual IEnumerable<string> ValidateRoleProperty( string type, string value )
        {
            return Enumerable.Empty<string>();
        }
    }
}
