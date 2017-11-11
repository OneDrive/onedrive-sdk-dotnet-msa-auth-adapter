using Microsoft.Graph;
using System;
using System.Collections.Generic;
using System.Text;
using Xamarin.Forms;

namespace Microsoft.OneDrive.Sdk.Authentication.Ui
{
    public class FormsWebAuthenticationPage:ContentPage
    {
        FormsWebAuthenticationView v;
        public FormsWebAuthenticationPage(FormsWebAuthenticationUi webAuthenticationUi, Uri requestUri, Uri callbackUri)
        {
            Content = v = new FormsWebAuthenticationView();
            WebAuthenticationUi = webAuthenticationUi;
            RequestUri = requestUri;
            CallbackUri = callbackUri;
            Title = "OneDrive";
        }
        public Uri CallbackUri { get; private set; }
        public Uri RequestUri { get; private set; }
        public FormsWebAuthenticationUi WebAuthenticationUi { get; private set; }
        protected override bool OnBackButtonPressed()
        {
            v.Cancel();
            return base.OnBackButtonPressed();
        }

        protected override void OnAppearing()
        {
            v.Load(WebAuthenticationUi, RequestUri, CallbackUri);
            base.OnAppearing();
            v.BeginLoadAuthorizationUrl();
        }
    }
}
