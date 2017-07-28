using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.OneDrive.Sdk.Authentication
{
    public class AuthingEventArgs:EventArgs
    {
        public Uri CallbackUri { get; set; }
        public Uri RequestUri { get; set; }
    }
}
