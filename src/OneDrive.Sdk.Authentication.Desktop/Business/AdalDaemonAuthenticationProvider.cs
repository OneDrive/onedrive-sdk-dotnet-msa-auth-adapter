using System;
using System.Threading.Tasks;
using Microsoft.Graph;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Globalization;
using System.Threading;

namespace Microsoft.OneDrive.Sdk.Authentication.Business
{
    public class AdalDaemonAuthenticationProvider : IAuthenticationProvider
    {
        public AccountSession CurrentAccountSession { get; internal set; }
        string clientId;
        string clientKey;

        public AuthenticationContext authContext;
        ClientCredential clientCredential;

        // 'applicationId' : Your Application ID
        // 'applicationKey' : Your Application Key
        // 'tenant' : is usually a domain name for your Office365 service. Like 'yourcompany.onmicrosoft.com'
        public AdalDaemonAuthenticationProvider(
            string applicationId,
            string applicationKey,
            string tenant) 
        {
            clientId = applicationId;
            clientKey = applicationKey;

            string authority = String.Format(CultureInfo.InvariantCulture, "https://login.microsoftonline.com/{0}", tenant);
            authContext = new AuthenticationContext(authority);
            clientCredential = new ClientCredential(clientId, clientKey);
        }




        public async Task AuthenticateUserAsync(string serviceResourceId)
        {
            AuthenticationResult result = null;
            result = null;
            int retryCount = 0;
            bool retry = false;

            do
            {
                retry = false;
                try
                {
                    // ADAL includes an in memory cache, so this call will only send a message to the server if the cached token is expired.
                    result = await authContext.AcquireTokenAsync(serviceResourceId, clientCredential);
                }
                catch (AdalException ex)
                {
                    if (ex.ErrorCode == "temporarily_unavailable")
                    {
                        retry = true;
                        retryCount++;
                        Thread.Sleep(3000);
                    }

                    Console.WriteLine(
                        String.Format("An error occurred while acquiring a token\nTime: {0}\nError: {1}\nRetry: {2}\n",
                        DateTime.Now.ToString(),
                        ex.ToString(),
                        retry.ToString()));
                }

            } while ((retry == true) && (retryCount < 3));


            this.CurrentAccountSession = this.ConvertAuthenticationResultToAccountSession(result);
        }

        public async Task AuthenticateRequestAsync(HttpRequestMessage request)
        {
            if (this.CurrentAccountSession == null)
            {
                throw new ServiceException(
                    new Error
                    {
                        Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                        Message = "Please call one of the AuthenticateUserAsync...() methods to authenticate the user before trying to authenticate a request.",
                    });
            }

            if (this.CurrentAccountSession.IsExpiring)
            {
                throw new ServiceException(
                            new Error
                            {
                                Code = OAuthConstants.ErrorCodes.AuthenticationFailure,
                                Message = ""
                            });
            }

            var accessTokenType = string.IsNullOrEmpty(this.CurrentAccountSession.AccessTokenType)
                ? OAuthConstants.Headers.Bearer
                : this.CurrentAccountSession.AccessTokenType;

            var uri = new UriBuilder(request.RequestUri);
            if (string.IsNullOrEmpty(uri.Query))
                uri.Query = string.Format("client_secret={0}", clientKey);
            else
                uri.Query = uri.Query.TrimStart('?') + string.Format("&client_secret={0}", clientKey);
            request.RequestUri = uri.Uri;


            request.Headers.Authorization = new AuthenticationHeaderValue(
                accessTokenType,
                this.CurrentAccountSession.AccessToken);
        }

        protected AccountSession ConvertAuthenticationResultToAccountSession(AuthenticationResult authenticationResult)
        {
            if (authenticationResult == null)
            {
                return null;
            }

            return new AccountSession
            {
                AccessToken = authenticationResult.AccessToken,
                AccessTokenType = authenticationResult.AccessTokenType,
                ClientId = this.clientId,
                ExpiresOnUtc = authenticationResult.ExpiresOn,
                RefreshToken = authenticationResult.RefreshToken,
                UserId = authenticationResult.UserInfo == null ? null : authenticationResult.UserInfo.UniqueId,
            };
        }
    }
}
