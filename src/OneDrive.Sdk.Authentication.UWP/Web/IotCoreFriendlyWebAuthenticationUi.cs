using Microsoft.Graph;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.OneDrive.Sdk.Authentication
{
    public class IotCoreFriendlyWebAuthenticationUi : IWebAuthenticationUi
    {
        public async Task<IDictionary<string, string>> AuthenticateAsync(Uri requestUri, Uri callbackUri)
        {
            var authDialog = new IotCoreFriendlyWebAuthenticationUi();
            IDictionary<string, string> result = await authDialog.AuthenticateAsync(requestUri, callbackUri);
            if (result == null)
            {
                throw new ServiceException(new Error { Code = OAuthConstants.ErrorCodes.AuthenticationCancelled, Message = "Authentication cancelled by user." });
            }
            else
            {
                return result;
            }
        }
    }
}
