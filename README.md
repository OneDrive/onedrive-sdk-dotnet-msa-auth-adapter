# Authentication Adapter for the OneDrive SDK

This library makes it easy to to consume Microsoft account and Azure Active Directory authentication for the [OneDrive SDK](https://github.com/OneDrive/onedrive-sdk-csharp). It provides IAuthenticationProvider imlementations for Microsoft account OAuth and [ADAL](https://github.com/AzureAD/azure-activedirectory-library-for-dotnet) authentication.

The Authentication Adapter for the OneDrive SDK Library is built as a Portable Class Library. It targets the following frameworks:

* .NET 4.5+
* .NET for Windows Store apps
* Windows Phone 8.1 and higher

## Installation via NuGet

To install the client library via NuGet:

* Search for `Microsoft.OneDrive.Sdk.Authentication` in the NuGet Library, or
* Type `Install-Package Microsoft.OneDrive.Sdk.Authentication` into the Package Manager Console.

## Getting started

### 1. Register your application

Register your application to use Microsoft Graph API using one of the following
supported authentication portals:

* [Microsoft Application Registration Portal](https://apps.dev.microsoft.com):
  Register a new application that works with Microsoft Account and/or
  organizational accounts using the unified V2 Authentication Endpoint.
* [Microsoft Azure Active Directory](https://manage.windowsazure.com): Register
  a new application in your tenant's Active Directory to support work or school
  users for your tenant or multiple tenants.
  
### 2. Create a Microsoft account authentication provider

```csharp
var msaAuthenticationProvider = new MsaAuthenticationProvider(
        clientId,
        returnUrl,
        scopes);
```

The MsaAuthenticationProvider constructor has an overload that takes in client secret for platforms that support web clients.

#### Authenticate a user

```csharp
msaAuthenticationProvider.AuthenticateUserAsync();
```

AuthenticateUserAsync will perform the action of prompting the user with authentication UI.

### 2. Create an Azure Active Directory authentication provider

```csharp
var adalAuthenticationProvider = new AdalAuthenticationProvider(AccountSelection.AadClientId, AccountSelection.AadReturnUrl);
```

The AdalAuthenticationProvider constructor has an overload that takes in client secret or client certificate for platforms that support web clients.
The developer can also pass in an AuthenticationContext, in case the app is already using ADAL for authentication and would like to re-use their authentication context.

#### Look up service information for a user using Discovery Service

The DiscoveryServiceHelper is used to look up discovery service information for a user. It takes in an AdalAuthenticationProvider to authenticate the user for the discovery service endpoint.

```csharp
var discoveryServiceHelper = new DiscoveryServiceHelper(adalAuthenticationProvider);
var businessServiceInformation = await discoveryServiceHelper.DiscoverFilesEndpointInformationForUserAsync();
```

#### Authenticate a user, with possible UI prompt

```csharp
        await adalAuthenticationProvider.AuthenticateUserAsync(serviceResourceId);
```

#### Authenticate a user with refresh token

```csharp
        await adalAuthenticationProvider.AuthenticateUserWithRefreshTokenAsync(refreshToken, serviceResourceId);
```

serviceResourceId is optional when authenticating using a refresh token. If not provided, the access token will be granted for the resource that generated the refresh token.

#### Authenticate a user with an authorization code

```csharp
        await adalAuthenticationProvider.AuthenticateUserWithAuthorizationCodeAsync(authorizationCode, serviceResourceId);
```

serviceResourceId is optional when authenticating using an authorization code. If not provided, the access token will be granted for the resource that generated the code.

### 3. Create a Microsoft Graph client object with an authentication provider

```csharp
var client = new OneDriveClient(baseUrl, authenticationProvider);
```

## Sample projects


## Documentation and resources


## Issues

To view or log issues, see [issues](https://github.com/OneDrive/onedrive-sdk-dotnet-msa-auth-adapter/issues).

## Other resources

* NuGet Package: [https://www.nuget.org/packages/Microsoft.OneDrive.Sdk.Authentication](https://www.nuget.org/packages/Microsoft.OneDrive.Sdk.Authentication)


## License

Copyright (c) Microsoft Corporation. All Rights Reserved. Licensed under the MIT [license](LICENSE.txt)

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
