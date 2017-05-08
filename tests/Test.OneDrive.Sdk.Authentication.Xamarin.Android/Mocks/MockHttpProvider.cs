// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.Xamarin.Android.Mocks
{
    using System.Net.Http;
    using System.Threading.Tasks;

    using Microsoft.Graph;
    using System.Threading;
    public delegate void SendAsyncCallback(HttpRequestMessage request);

    public class MockHttpProvider : IHttpProvider
    {
        private HttpResponseMessage httpResponseMessage;

        public MockHttpProvider(HttpResponseMessage httpResponseMessage, ISerializer serializer = null)
        {
            this.httpResponseMessage = httpResponseMessage;
            this.Serializer = serializer;
        }

        public SendAsyncCallback OnSendAsync { get; set; }

        public ISerializer Serializer { get; private set; }

        public void Dispose()
        {
            this.httpResponseMessage.Dispose();
        }

        public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
        {
            return this.SendAsync(request, HttpCompletionOption.ResponseContentRead, CancellationToken.None);
        }

        public Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            HttpCompletionOption completionOption,
            CancellationToken cancellationToken)
        {
            if (this.OnSendAsync != null)
            {
                this.OnSendAsync(request);
            }

            return Task.FromResult(this.httpResponseMessage);
        }
    }
}
