﻿// ------------------------------------------------------------------------------
//  Copyright (c) 2015 Microsoft Corporation
// 
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
// 
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
// 
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
// ------------------------------------------------------------------------------

namespace Test.OneDrive.Sdk.Authentication.UWP.Mocks
{
    using System;
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
