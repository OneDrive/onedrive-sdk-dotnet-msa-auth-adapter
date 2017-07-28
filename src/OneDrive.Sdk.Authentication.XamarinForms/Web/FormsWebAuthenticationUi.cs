using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.OneDrive.Sdk.Authentication
{
    public class FormsWebAuthenticationUi : IWebAuthenticationUi
    {
        public event EventHandler<AuthCompletedEventArgs> Completed;
        public event EventHandler<AuthFailedEventArgs> Failed;
        public Task<IDictionary<string, string>> AuthenticateAsync(Uri requestUri, Uri callbackUri)
        {
            TaskCompletionSource<IDictionary<string, string>> tcs = new TaskCompletionSource<IDictionary<string, string>>();

            this.Completed += (s, e) =>
            {
                tcs.SetResult(e.AuthorizationParameters);
            };

            this.Failed += (s, e) =>
            {
                tcs.SetException(e.Error);
            };


            return tcs.Task;
        }

        internal void OnCompleted(AuthCompletedEventArgs e)
        {
            Completed?.Invoke(this, e);
        }

        internal void OnFailed(AuthFailedEventArgs e)
        {
            Failed?.Invoke(this, e);
        }
    }
}
