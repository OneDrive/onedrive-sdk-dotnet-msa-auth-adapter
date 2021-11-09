﻿// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk.Authentication
{
    using Microsoft.Graph;
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Http;
    using System.Text;
    using System.Threading.Tasks;

    public class OAuthHelper
    {
        public async Task<string> GetAuthorizationCodeAsync(
            string clientId,
            string returnUrl,
            string[] scopes,
            IWebAuthenticationUi webAuthenticationUi,
            string userId = null)
        {
            if (webAuthenticationUi != null)
            {
                var requestUri = new Uri(
                    this.GetAuthorizationCodeRequestUrl(
                        clientId,
                        returnUrl,
                        scopes,
                        userId));

                var authenticationResponseValues = await webAuthenticationUi.AuthenticateAsync(
                    requestUri,
                    new Uri(returnUrl)).ConfigureAwait(false);

                OAuthErrorHandler.ThrowIfError(authenticationResponseValues);

                string code;
                if (authenticationResponseValues != null && authenticationResponseValues.TryGetValue("code", out code))
                {
                    return code;
                }
            }

            return null;
        }

        /// <summary>
        /// Gets the request URL for OAuth authentication using the code flow.
        /// </summary>
        /// <param name="clientId">The ID of the application.</param>
        /// <param name="returnUrl">The return URL for the request. Defaults to the service info value.</param>
        /// <returns>The OAuth request URL.</returns>
        public string GetAuthorizationCodeRequestUrl(string clientId, string returnUrl, string[] scopes, string userId = null)
        {
            var requestUriStringBuilder = new StringBuilder();
            requestUriStringBuilder.Append(OAuthConstants.MicrosoftAccountAuthenticationServiceUrl);
            requestUriStringBuilder.AppendFormat("?{0}={1}", OAuthConstants.RedirectUriKeyName, returnUrl);
            requestUriStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ClientIdKeyName, clientId);

            if (scopes != null)
            {
                requestUriStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ScopeKeyName, WebUtility.UrlEncode(string.Join(" ", scopes)));
            }

            if (!string.IsNullOrEmpty(userId))
            {
                requestUriStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.UserIdKeyName, userId);
            }

            requestUriStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ResponseTypeKeyName, OAuthConstants.CodeKeyName);

            return requestUriStringBuilder.ToString();
        }

        /// <summary>
        /// Gets the request body for redeeming an authorization code for an access token.
        /// </summary>
        /// <param name="code">The authorization code to redeem.</param>
        /// <param name="clientId">The ID of the application.</param>
        /// <param name="returnUrl">The return URL for the request. Defaults to the service info value.</param>
        /// <returns>The request body for the code redemption call.</returns>
        public string GetAuthorizationCodeRedemptionRequestBody(string code, string clientId, string returnUrl, string[] scopes, string clientSecret = null)
        {
            var requestBodyStringBuilder = new StringBuilder();
            requestBodyStringBuilder.AppendFormat("{0}={1}", OAuthConstants.RedirectUriKeyName, returnUrl);
            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ClientIdKeyName, clientId);

            if (scopes != null)
            {
                requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ScopeKeyName, WebUtility.UrlEncode(string.Join(" ", scopes)));
            }

            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.CodeKeyName, code);
            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.GrantTypeKeyName, OAuthConstants.AuthorizationCodeGrantType);

            if (!string.IsNullOrEmpty(clientSecret))
            {
                requestBodyStringBuilder.AppendFormat("&client_secret={0}", clientSecret);
            }

            return requestBodyStringBuilder.ToString();
        }

        /// <summary>
        /// Gets the request body for redeeming a refresh token for an access token.
        /// </summary>
        /// <param name="refreshToken">The refresh token to redeem.</param>
        /// <returns>The request body for the redemption call.</returns>
        public string GetRefreshTokenRequestBody(string refreshToken, string clientId, string returnUrl, string[] scopes, string clientSecret = null)
        {
            var requestBodyStringBuilder = new StringBuilder();
            requestBodyStringBuilder.AppendFormat("{0}={1}", OAuthConstants.RedirectUriKeyName, returnUrl);
            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ClientIdKeyName, clientId);

            if (scopes != null)
            {
                requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ScopeKeyName, WebUtility.UrlEncode(string.Join(" ", scopes)));
            }

            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.RefreshTokenKeyName, refreshToken);
            requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.GrantTypeKeyName, OAuthConstants.RefreshTokenKeyName);

            if (!string.IsNullOrEmpty(clientSecret))
            {
                requestBodyStringBuilder.AppendFormat("&{0}={1}", OAuthConstants.ClientSecretKeyName, clientSecret);
            }

            return requestBodyStringBuilder.ToString();
        }

        public string GetSignOutUrl(string clientId, string returnUrl)
        {
            return string.Format(
                "{0}?client_id={1}&redirect_uri={2}",
                OAuthConstants.MicrosoftAccountSignOutUrl,
                clientId,
                returnUrl);
        }

        public async Task<AccountSession> RedeemAuthorizationCodeAsync(
            string authorizationCode,
            string clientId,
            string clientSecret,
            string returnUrl,
            string[] scopes)
        {
            using (var httpProvider = new HttpProvider())
            {
                return await this.RedeemAuthorizationCodeAsync(
                    authorizationCode,
                    clientId,
                    clientSecret,
                    returnUrl,
                    scopes,
                    httpProvider).ConfigureAwait(false);
            }
        }

        public async Task<AccountSession> RedeemAuthorizationCodeAsync(
            string authorizationCode,
            string clientId,
            string clientSecret,
            string returnUrl,
            string[] scopes,
            IHttpProvider httpProvider)
        {
            if (string.IsNullOrEmpty(authorizationCode))
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Authorization code is required to redeem."
                    });
            }

            return await this.SendTokenRequestAsync(
                this.GetAuthorizationCodeRedemptionRequestBody(
                    authorizationCode,
                    clientId,
                    returnUrl,
                    scopes,
                    clientSecret),
                httpProvider).ConfigureAwait(false);
        }

        public async Task<AccountSession> RedeemRefreshTokenAsync(
            string refreshToken,
            string clientId,
            string returnUrl,
            string[] scopes)
        {
            return await this.RedeemRefreshTokenAsync(
                refreshToken,
                clientId,
                /* clientSecret */ null,
                returnUrl,
                scopes,
                /* httpProvider */ null).ConfigureAwait(false);
        }

        public async Task<AccountSession> RedeemRefreshTokenAsync(
            string refreshToken,
            string clientId,
            string returnUrl,
            string[] scopes,
            IHttpProvider httpProvider)
        {
            return await this.RedeemRefreshTokenAsync(
                refreshToken,
                clientId,
                /* clientSecret */ null,
                returnUrl,
                scopes,
                httpProvider).ConfigureAwait(false);
        }

        public async Task<AccountSession> RedeemRefreshTokenAsync(
            string refreshToken,
            string clientId,
            string clientSecret,
            string returnUrl,
            string[] scopes)
        {
            return await this.RedeemRefreshTokenAsync(
                refreshToken,
                clientId,
                clientSecret,
                returnUrl,
                scopes,
                /* httpProvider */ null).ConfigureAwait(false);
        }

        public async Task<AccountSession> RedeemRefreshTokenAsync(
            string refreshToken,
            string clientId,
            string clientSecret,
            string returnUrl,
            string[] scopes,
            IHttpProvider httpProvider)
        {
            if (string.IsNullOrEmpty(refreshToken))
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Refresh token is required to redeem."
                    });
            }

            var tokenRequestBody = this.GetRefreshTokenRequestBody(
                refreshToken,
                clientId,
                returnUrl,
                scopes,
                clientSecret);

            if (httpProvider == null)
            {
                return await this.SendTokenRequestAsync(tokenRequestBody);
            }

            return await this.SendTokenRequestAsync(tokenRequestBody, httpProvider).ConfigureAwait(false);
        }

        public async Task<AccountSession> SendTokenRequestAsync(string requestBodyString)
        {
            using (var httpProvider = new HttpProvider())
            {
                return await this.SendTokenRequestAsync(requestBodyString, httpProvider).ConfigureAwait(false);
            }
        }

        public async Task<AccountSession> SendTokenRequestAsync(string requestBodyString, IHttpProvider httpProvider)
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, OAuthConstants.MicrosoftAccountTokenServiceUrl);

            httpRequestMessage.Content = new StringContent(requestBodyString, Encoding.UTF8, "application/x-www-form-urlencoded");

            using (var authResponse = await httpProvider.SendAsync(httpRequestMessage).ConfigureAwait(false))
            {
                var responseContentStr = await authResponse.Content.ReadAsStringAsync().ConfigureAwait(false);

                //the default http provider serializer will fail to coerce numeric values into strings,
                //and throws an exception that prevents this scenario from working. 
                //instead, we'll establish a baseline deserialization, without circumventing use of any
                //User-defined serializer should one be present.

                //create a fallback deserialization
                var responseParsedAsJson = Newtonsoft.Json.Linq.JObject.Parse(responseContentStr);
                IDictionary<string, string> responseJsonAsDict = responseParsedAsJson.ToObject<Dictionary<string, string>>();

                //attempt to use the http provider's deserializer, but ignore it if it fails
                try
                {
                    responseJsonAsDict = httpProvider.Serializer.DeserializeObject<IDictionary<string, string>>(
                            responseContentStr);
                }
                catch (Exception) { }

                if (responseJsonAsDict != null)
                {
                    OAuthErrorHandler.ThrowIfError(responseJsonAsDict);
                    return new AccountSession(responseJsonAsDict);
                }

                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Authentication failed. No response values returned from authentication flow."
                    });
            }
        }
    }
}
