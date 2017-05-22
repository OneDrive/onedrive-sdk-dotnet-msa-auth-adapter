using Microsoft.Graph;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

// The Content Dialog item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace Microsoft.OneDrive.Sdk.Authentication
{
    public sealed partial class IotFriendlyWebDialog : ContentDialog, INotifyPropertyChanged
    {
        private IDictionary<string, string> authenticationResponseValues = null;
        private Uri callbackUri;
        private TaskCompletionSource<bool> dialogTaskComplete = new TaskCompletionSource<bool>();

        private Uri webViewSource;
        public Uri WebViewSource
        {
            get { return webViewSource; }
            internal set
            {
                if (webViewSource != value)
                {
                    webViewSource = value;
                    RaisePropertyChanged();
                }
            }
        }

        public IotFriendlyWebDialog()
        {
            this.InitializeComponent();
        }   
        
        public async Task<IDictionary<string, string>> GetAuthenticationResponseValue(Uri requestUri, Uri callbackUri)
        {
            bool isSignOutRequest = 
                requestUri.AbsoluteUri.StartsWith(OAuthConstants.MicrosoftAccountSignOutUrl,
                    StringComparison.OrdinalIgnoreCase);

            this.callbackUri = callbackUri;
            this.DialogWebView.Navigate(requestUri);

            if (!isSignOutRequest)
            {
                await Task.WhenAll(this.ShowAsync().AsTask(), this.dialogTaskComplete.Task);
            }
            else
            {
                await dialogTaskComplete.Task;
            }

            return this.authenticationResponseValues;
        }

        private void ContentDialog_Closing(ContentDialog sender, ContentDialogClosingEventArgs args)
        {
            this.dialogTaskComplete.TrySetResult(true);
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.authenticationResponseValues = null;            
            this.Hide();
            this.dialogTaskComplete.TrySetResult(true);
        }        

        private void DialogWebView_NavigationStarting(WebView sender, WebViewNavigationStartingEventArgs args)
        {
            if (this.NavigatedToCallbackUrl(args.Uri))
            {
                args.Cancel = true;
                this.authenticationResponseValues = UrlHelper.GetQueryOptions(args.Uri);                
                this.Hide();
                this.dialogTaskComplete.TrySetResult(true);
            }
        }        

        private void DialogWebView_NavigationCompleted(WebView sender, WebViewNavigationCompletedEventArgs args)
        {
            if (this.NavigatedToCallbackUrl(args.Uri))
            {
                this.authenticationResponseValues = UrlHelper.GetQueryOptions(args.Uri);
                this.dialogTaskComplete.TrySetResult(true);
                this.Hide();
            }
        }

        private bool NavigatedToCallbackUrl(Uri uri)
        {
            return uri.Authority.Equals(
                this.callbackUri.Authority, StringComparison.OrdinalIgnoreCase)
                    && uri.AbsolutePath.Equals(this.callbackUri.AbsolutePath);
        }

        public event PropertyChangedEventHandler PropertyChanged;
        private void RaisePropertyChanged([CallerMemberName]string property = "")
        {
            this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
        }
    }
}
