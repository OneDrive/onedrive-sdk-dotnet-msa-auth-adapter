// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    public static class OAuthConstants
    {
        public const string AccessTokenKeyName = "access_token";

        public const string AuthenticationCancelled = "authentication_cancelled";

        public const string AuthorizationCodeGrantType = "authorization_code";

        public const string AuthorizationServiceKey = "authorization_service";

        public const string ClientIdKeyName = "client_id";

        public const string ClientSecretKeyName = "client_secret";

        public const string CodeKeyName = "code";

        public const string DiscoveryResourceKey = "discovery_resource";

        public const string DiscoveryServiceKey = "discovery_service";

        public const string ErrorDescriptionKeyName = "error_description";

        public const string ErrorKeyName = "error";
            
        public const string ExpiresInKeyName = "expires_in";

        public const string GrantTypeKeyName = "grant_type";

        public const string RedirectUriKeyName = "redirect_uri";

        public const string RefreshTokenKeyName = "refresh_token";

        public const string ResponseTypeKeyName = "response_type";

        public const string ScopeKeyName = "scope";

        public const string TokenResponseTypeValueName = "token";

        public const string TokenServiceKey = "token_service";

        public const string TokenTypeKeyName = "token_type";
            
        public const string UserIdKeyName = "user_id";

        public const string ActiveDirectoryAuthenticationServiceUrl = "https://login.microsoftonline.com/common/oauth2/authorize";

        public const string ActiveDirectoryAuthenticationServiceUrlFormatString = "https://login.microsoftonline.com/{0}";

        public const string ActiveDirectoryDiscoveryResource = "https://api.office.com/discovery/";

        public const string ActiveDirectoryDiscoveryServiceUrl = "https://api.office.com/discovery/v2.0/me/services";

        public const string ActiveDirectorySignOutUrl = "https://login.microsoftonline.com/common/oauth2/logout";

        public const string MicrosoftAccountAuthenticationServiceUrl = "https://login.live.com/oauth20_authorize.srf";

        public const string MicrosoftAccountSignOutUrl = "https://login.live.com/oauth20_logout.srf";

        public const string MicrosoftAccountTokenServiceUrl = "https://login.live.com/oauth20_token.srf";

        public static class ErrorCodes
        {
            public const string AuthenticationCancelled = "authenticationCancelled";

            public const string AuthenticationFailure = "authenticationFailure";
        }
    }
}
