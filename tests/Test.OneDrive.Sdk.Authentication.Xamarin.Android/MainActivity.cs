// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------
using System.Reflection;
using Android.App;
using Android.OS;
using Xamarin.Android.NUnitLite;

namespace Test.OneDrive.Sdk.Authentication.Xamarin.Android
{
    [Activity(Label = "Test.OneDrive.Sdk.Xamarin.Android", MainLauncher = true, Icon = "@drawable/icon")]
    public class MainActivity : TestSuiteActivity
    {
        protected override void OnCreate(Bundle bundle)
        {
            base.AddTest(Assembly.GetExecutingAssembly());
            base.OnCreate(bundle);
        }
    }
}

