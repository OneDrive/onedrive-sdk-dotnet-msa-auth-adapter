using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.OneDrive.Sdk.Authentication
{
    public class FormsWebAuthenticationUi : IWebAuthenticationUi
    {
        public FormsWebAuthenticationUi()
        {

        }
        public Xamarin.Forms.INavigation Navigation { get;private set; }
        public FormsWebAuthenticationUi(Xamarin.Forms.INavigation navigation)
        {
            Navigation = navigation;
        }
        public event EventHandler<AuthCompletedEventArgs> Completed;
        public event EventHandler<AuthFailedEventArgs> Failed;
        public event EventHandler<AuthingEventArgs> Authing;
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

            Navigation?.PushAsync(new Ui.FormsWebAuthenticationPage(this, requestUri, callbackUri));
            Authing?.Invoke(this, new AuthingEventArgs() { RequestUri = requestUri, CallbackUri = callbackUri });


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
