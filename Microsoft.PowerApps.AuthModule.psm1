$local:ErrorActionPreference = "Stop"

Add-Type -AssemblyName (Join-Path (Split-Path $script:MyInvocation.MyCommand.Path) "Microsoft.PowerPlatform.Samples.Authentication.dll") -PassThru

function Get-JwtTokenClaims
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$JwtToken
    )

    $tokenSplit = $JwtToken.Split(".")
    $claimsSegment = $tokenSplit[1].Replace(" ", "+").Replace("-", "+").Replace('_', '/');
    
    $mod = $claimsSegment.Length % 4
    if ($mod -gt 0)
    {
        $paddingCount = 4 - $mod;
        for ($i = 0; $i -lt $paddingCount; $i++)
        {
            $claimsSegment += "="
        }
    }

    $decodedClaimsSegment = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($claimsSegment))

    return ConvertFrom-Json $decodedClaimsSegment
}

function Add-PowerAppsAccount
{
    <#
    .SYNOPSIS
    Add PowerApps account.
    .DESCRIPTION
    The Add-PowerAppsAccount cmdlet logins the user or application account and save login information to cache. 
    Use Get-Help Add-PowerAppsAccount -Examples for more detail.
    .PARAMETER Audience
    The service audience which is used for login.
    .PARAMETER Endpoint
    The serivce endpoint which to call. The value can be "prod","preview","tip1", "tip2", "usgov", "dod", or "usgovhigh".
    .PARAMETER Username
    The user name used for login.
    .PARAMETER Password
    The password for the user.
    .PARAMETER TenantID
    The tenant Id of the user or application.
    .PARAMETER CertificateThumbprint
    The certificate thumbprint of the application.
    .PARAMETER ClientSecret
    The client secret of the application.
    .PARAMETER SecureClientSecret
    The secure client secret of the application.
    .PARAMETER ApplicationId
    The application Id.
    .EXAMPLE
    Add-PowerAppsAccount
    Login to "prod" endpoint.
    .EXAMPLE
    Add-PowerAppsAccount -Endpoint "prod" -Username "username@test.onmicrosoft.com" -Password "password"
    Login to "prod" for user "username@test.onmicrosoft.com" by using password "password"
    .EXAMPLE
    Add-PowerAppsAccount `
      -Endpoint "tip1" `
      -TenantID 1a1fbe33-1ff4-45b2-90e8-4628a5112345 `
      -ClientSecret ABCDE]NO_8:YDLp0J4o-:?=K9cmipuF@ `
      -ApplicationId abcdebd6-e62c-4f68-ab74-b046579473ad
    Login to "tip1" for application abcdebd6-e62c-4f68-ab74-b046579473ad in tenant 1a1fbe33-1ff4-45b2-90e8-4628a5112345 by using client secret.
    .EXAMPLE
    Add-PowerAppsAccount `
      -Endpoint "tip1" `
      -TenantID 1a1fbe33-1ff4-45b2-90e8-4628a5112345 `
      -CertificateThumbprint 12345137C1B2D4FED804DB353D9A8A18465C8027 `
      -ApplicationId 08627eb8-8eba-4a9a-8c49-548266012345
    Login to "tip1" for application 08627eb8-8eba-4a9a-8c49-548266012345 in tenant 1a1fbe33-1ff4-45b2-90e8-4628a5112345 by using certificate.
    #>
    [CmdletBinding()]
    param
    (
        [string] $Audience = "https://management.azure.com/",

        [Parameter(Mandatory = $false)]
        [ValidateSet("prod","preview","tip1", "tip2", "usgov", "usgovhigh", "dod")]
        [string]$Endpoint = "prod",

        [string]$Username = $null,

        [SecureString]$Password = $null,

        [string]$TenantID = $null,

        [string]$CertificateThumbprint = $null,

        [string]$ClientSecret = $null,

        [SecureString]$SecureClientSecret = $null,

        [string]$ApplicationId = "1950a258-227b-4e31-a9cf-717495945fc2"
    )

    $authBaseUri =
        switch ($Endpoint)
            {
                "usgovhigh" { "https://login.microsoftonline.us" }
                "dod"       { "https://login.microsoftonline.us" }
                default     { "https://login.windows.net" }
            };

    $scopes =  @("$Audience/user_impersonation", "https://service.powerapps.com/user_impersonation")
    $authResult = [Microsoft.PowerPlatform.CenterOfExcellence.Authentication.ActiveDirectoryAuth]::GetDeviceCodeAccessToken($ApplicationId, "$authBaseUri/common", @("$Audience/user_impersonation"))

    $claims = Get-JwtTokenClaims -JwtToken $authResult.AccessToken
    
    #$authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("$authBaseUri/common");
    #$redirectUri = New-Object System.Uri("urn:ietf:wg:oauth:2.0:oob");
        
    <#

    if (![string]::IsNullOrWhiteSpace($TenantID) -and ![string]::IsNullOrWhiteSpace($CertificateThumbprint))
    {
        $AuthUri = "$authBaseUri/$TenantID/oauth2/authorize"
        $clientCertificate = Get-Item -Path Cert:\CurrentUser\My\$CertificateThumbprint
        $authenticationContext = New-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList $AuthUri
        $certificateCredential = New-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate -ArgumentList ($ApplicationId, $clientCertificate)
        $authResult = $authenticationContext.AcquireToken($Audience, $certificateCredential)
        $claims = Get-JwtTokenClaims -JwtToken $authResult.AccessToken
    }
    elseif (![string]::IsNullOrWhiteSpace($ClientSecret) -or $SecureClientSecret -ne $null)
    {
        $AuthUri = "$authBaseUri/$TenantID/oauth2/authorize"
        $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext($AuthUri)

        if ($SecureClientSecret -ne $null)
        {
            $credential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential($ApplicationId, $SecureClientSecret)
        }
        else
        {
            $credential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential($ApplicationId, $ClientSecret)
        }

        $authResult = $authContext.AcquireToken($Audience, $credential)
        $claims = Get-JwtTokenClaims -JwtToken $authResult.AccessToken
    }
    elseif ($Username -ne $null -and $Password -ne $null)
    {
        $credential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential($Username, $Password)
        $authResult = $authContext.AcquireToken($Audience, $ApplicationId, $credential);
        $claims = Get-JwtTokenClaims -JwtToken $authResult.IdToken
    }
    else {
        $authResult = $authContext.AcquireToken($Audience, $ApplicationId, $redirectUri, 1);
        $claims = Get-JwtTokenClaims -JwtToken $authResult.IdToken
    }
    #>

    $global:currentSession = @{
        loggedIn = $true;
        idToken = $authResult.IdToken;
        upn = $claims.upn;
        tenantId = $claims.tid;
        userId = $claims.oid;
        applicationId = $claims.appid;
        certificateThumbprint = $CertificateThumbprint;
        clientSecret = $ClientSecret;
        secureClientSecret = $SecureClientSecret;
        refreshToken = $authResult.RefreshToken;
        expiresOn = (Get-Date).AddHours(8);
        resourceTokens = @{
            $Audience = @{
                accessToken = $authResult.AccessToken;
                expiresOn = $authResult.ExpiresOn;
            }
            "https://service.powerapps.com/" = @{
                accessToken = $authResult.AccessToken;
                expiresOn = $authResult.ExpiresOn;
            }
        };
        selectedEnvironment = "~default";
        authBaseUri = $authBaseUri;
        flowEndpoint = 
            switch ($Endpoint)
            {
                "prod"      { "api.flow.microsoft.com" }
                "usgov"     { "gov.api.flow.microsoft.us" }
                "usgovhigh" { "high.api.flow.microsoft.us" }
                "dod"       { "api.flow.appsplatform.us" }
                "china"     { "api.powerautomate.cn" }
                "preview"   { "preview.api.flow.microsoft.com" }
                "tip1"      { "tip1.api.flow.microsoft.com"}
                "tip2"      { "tip2.api.flow.microsoft.com" }
                default     { throw "Unsupported endpoint '$Endpoint'"}
            };
        powerAppsEndpoint = 
            switch ($Endpoint)
            {
                "prod"      { "api.powerapps.com" }
                "usgov"     { "gov.api.powerapps.us" }
                "usgovhigh" { "high.api.powerapps.us" }
                "dod"       { "api.apps.appsplatform.us" }
                "china"     { "api.powerapps.cn" }
                "preview"   { "preview.api.powerapps.com" }
                "tip1"      { "tip1.api.powerapps.com"}
                "tip2"      { "tip2.api.powerapps.com" }
                default     { throw "Unsupported endpoint '$Endpoint'"}
            };            
        bapEndpoint = 
            switch ($Endpoint)
            {
                "prod"      { "api.bap.microsoft.com" }
                "usgov"     { "gov.api.bap.microsoft.us" }
                "usgovhigh" { "high.api.bap.microsoft.us" }
                "dod"       { "api.bap.appsplatform.us" }
                "china"     { "api.bap.partner.microsoftonline.cn" }
                "preview"   { "preview.api.bap.microsoft.com" }
                "tip1"      { "tip1.api.bap.microsoft.com"}
                "tip2"      { "tip2.api.bap.microsoft.com" }
                default     { throw "Unsupported endpoint '$Endpoint'"}
            };      
        graphEndpoint = 
            switch ($Endpoint)
            {
                "prod"      { "graph.windows.net" }
                "usgov"     { "graph.windows.net" }
                "usgovhigh" { "graph.windows.net" }
                "dod"       { "graph.windows.net" }
                "china"     { "graph.windows.net" }
                "preview"   { "graph.windows.net" }
                "tip1"      { "graph.windows.net"}
                "tip2"      { "graph.windows.net" }
                default     { throw "Unsupported endpoint '$Endpoint'"}
            };
        cdsOneEndpoint = 
            switch ($Endpoint)
            {
                "prod"      { "api.cds.microsoft.com" }
                "usgov"     { "gov.api.cds.microsoft.us" }
                "usgovhigh" { "high.api.cds.microsoft.us" }
                "dod"       { "dod.gov.api.cds.microsoft.us" }
                "preview"   { "preview.api.cds.microsoft.com" }
                "tip1"      { "tip1.api.cds.microsoft.com"}
                "tip2"      { "tip2.api.cds.microsoft.com" }
                default     { throw "Unsupported endpoint '$Endpoint'"}
            };
    };
}

function Test-PowerAppsAccount
{
    <#
    .SYNOPSIS
    Test PowerApps account.
    .DESCRIPTION
    The Test-PowerAppsAccount cmdlet checks cache and calls Add-PowerAppsAccount if user account is not in cache.
    Use Get-Help Test-PowerAppsAccount -Examples for more detail.
    .EXAMPLE
    Test-PowerAppsAccount
    Check if user account is cached.
    #>
    [CmdletBinding()]
    param
    (
    )

    if (-not $global:currentSession)
    {
        Add-PowerAppsAccount
    }
}

function Remove-PowerAppsAccount
{
    <#
    .SYNOPSIS
    Remove PowerApps account.
    .DESCRIPTION
    The Remove-PowerAppsAccount cmdlet removes the user or application login information from cache.
    Use Get-Help Remove-PowerAppsAccount -Examples for more detail.
    .EXAMPLE
    Remove-PowerAppsAccount
    Removes the login information from cache.
    #>
    [CmdletBinding()]
    param
    (
    )

    if ($global:currentSession -ne $null -and $global:currentSession.upn -ne $null)
    {
        Write-Verbose "Logging out $($global:currentSession.upn)"
    }
    else
    {
        Write-Verbose "No user logged in"
    }

    $global:currentSession = @{
        loggedIn = $false;
    };
}

function Get-JwtToken
{
    <#
    .SYNOPSIS
    Get user login token.
    .DESCRIPTION
    The Get-JwtToken cmdlet get the user or application login information from cache. It will call Add-PowerAppsAccount if login token expired.
    Use Get-Help Get-JwtToken -Examples for more detail.
    .EXAMPLE
    Get-JwtToken "https://service.powerapps.com/"
    Get login token for PowerApps "prod".
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string] $Audience
    )

    if ($global:currentSession -eq $null)
    {
        $global:currentSession = @{
            loggedIn = $false;
        };
    }

    if ($global:currentSession.loggedIn -eq $false -or $global:currentSession.expiresOn -lt (Get-Date))
    {
        Write-Verbose "No user logged in. Signing the user in before acquiring token."

        if (![string]::IsNullOrWhiteSpace($($global:currentSession.certificateThumbprint)))
        {
            Add-PowerAppsAccount `
              -Audience $Audience `
              -TenantID $global:currentSession.tenantId `
              -CertificateThumbprint $global:currentSession.certificateThumbprint `
              -ApplicationId $global:currentSession.applicationId
        }
        else
        {
            Add-PowerAppsAccount -Audience $Audience
        }
    }

    if ($global:currentSession.resourceTokens[$Audience] -eq $null -or `
        $global:currentSession.resourceTokens[$Audience].accessToken -eq $null -or `
        $global:currentSession.resourceTokens[$Audience].expiresOn -eq $null -or `
        $global:currentSession.resourceTokens[$Audience].expiresOn -lt (Get-Date))
    {

        Write-Verbose "Token for $Audience is either missing or expired. Acquiring a new one."

        $authBaseUri = $global:currentSession.authBaseUri
        $tenantId = $global:currentSession.tenantId
        if (![string]::IsNullOrWhiteSpace($global:currentSession.certificateThumbprint))
        {
            $AuthUri = "$authBaseUri/$tenantId/oauth2/authorize"
            $clientCertificate = Get-Item -Path Cert:\CurrentUser\My\$($global:currentSession.certificateThumbprint)
            $authenticationContext = New-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList $AuthUri
            $certificateCredential = New-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate -ArgumentList ($global:currentSession.applicationId, $clientCertificate)
            $authResult = $authenticationContext.AcquireToken($Audience, $certificateCredential)
            $global:currentSession.resourceTokens[$Audience] = @{
                accessToken = $authResult.AccessToken;
                expiresOn = $authResult.ExpiresOn;
            }
        }
        elseif (![string]::IsNullOrWhiteSpace($global:currentSession.clientSecret) -or $global:currentSession.secureClientSecret -ne $null)
        {
            $AuthUri = "$authBaseUri/$TenantID/oauth2/authorize"
            $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext($AuthUri)

            if ($global:currentSession.secureClientSecret -ne $null)
            {
                $credential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential($global:currentSession.applicationId, $global:currentSession.secureClientSecret)
            }
            else
            {
                $credential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential($global:currentSession.applicationId, $global:currentSession.clientSecret)
            }

            $authResult = $authContext.AcquireToken($Audience, $credential)
            $global:currentSession.resourceTokens[$Audience] = @{
                accessToken = $authResult.AccessToken;
                expiresOn = $authResult.ExpiresOn;
            }
        }
        else
        {
            try
            {
                $refreshTokenResult = [Microsoft.PowerPlatform.CenterOfExcellence.Authentication.ActiveDirectoryAuth]::GetDeviceCodeAccessToken("1950a258-227b-4e31-a9cf-717495945fc2","$authBaseUri/$tenantId", @("$Audience/user_impersonation"), $Audience)

                $global:currentSession.resourceTokens[$Audience] = @{
                    accessToken = $refreshTokenResult.AccessToken;
                    expiresOn = $refreshTokenResult.ExpiresOn;
                }
            }
            catch
            {
                if ($_.Exception.InnerException -and $_.Exception.InnerException.ErrorCode -eq "interaction_required")
                {
                    Write-Verbose "Token for $Audience requires additional claims."

                    $redirectUri = New-Object System.Uri("urn:ietf:wg:oauth:2.0:oob")
                    $authResult = $authContext.AcquireToken($Audience, "1950a258-227b-4e31-a9cf-717495945fc2", $redirectUri, 1);
                    $global:currentSession.resourceTokens[$Audience] = @{
                        accessToken = $authResult.AccessToken;
                        expiresOn = $authResult.ExpiresOn;
                    }
                }
                else
                {
                    throw
                }
            }
        }
    }

    return $global:currentSession.resourceTokens[$Audience].accessToken;
}

function Invoke-OAuthDialog
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string] $ConsentLinkUri
    )

    Add-Type -AssemblyName System.Windows.Forms
    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width=440; Height=640 }
    $web  = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width=420; Height=600; Url=$ConsentLinkUri }
    $DocComp  = {
        $Global:uri = $web.Url.AbsoluteUri        
        if ($Global:uri -match "error=[^&]*|code=[^&]*")
        {
            $form.Close()
        }
    }
    $web.ScriptErrorsSuppressed = $true
    $web.Add_DocumentCompleted($DocComp)
    $form.Controls.Add($web)
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() | Out-Null
    $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)

    $output = @{}

    foreach($key in $queryOutput.Keys)
    {
        $output["$key"] = $queryOutput[$key]
    }
    
    return $output
}


function Get-TenantDetailsFromGraph
{
    <#
    .SYNOPSIS
    Get my organization tenant details from graph.
    .DESCRIPTION
    The Get-TenantDetailsFromGraph function calls graph and gets my organization tenant details. 
    Use Get-Help Get-TenantDetailsFromGraph -Examples for more detail.
    .PARAMETER GraphApiVersion
    Graph version to call. The default version is "1.6".
    .EXAMPLE
    Get-TenantDetailsFromGraph
    Get my organization tenant details from graph by calling graph service in version 1.6.
    #>
    param
    (
        [string]$GraphApiVersion = "1.6"
    )

    process 
    {
        $TenantIdentifier = "myorganization"

        $route = "https://{graphEndpoint}/{tenantIdentifier}/tenantDetails`?api-version={graphApiVersion}" `
        | ReplaceMacro -Macro "{tenantIdentifier}" -Value $TenantIdentifier `
        | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

        $graphResponse = InvokeApi -Method GET -Route $route
        
        if ($graphResponse.value -ne $null)
        {
            CreateTenantObject -TenantObj $graphResponse.value
        }
        else
        {
            return $graphResponse
        }
    }
}

#Returns users or groups from Graph
#wrapper on top of https://msdn.microsoft.com/en-us/library/azure/ad/graph/api/users-operations & https://msdn.microsoft.com/en-us/library/azure/ad/graph/api/groups-operations 
function Get-UsersOrGroupsFromGraph(
)
{
    <#
    .SYNOPSIS
    Returns users or groups from Graph.
    .DESCRIPTION
    The Get-UsersOrGroupsFromGraph function calls graph and gets users or groups from Graph. 
    Use Get-Help Get-UsersOrGroupsFromGraph -Examples for more detail.
    .PARAMETER ObjectId
    User objec Id.
    .PARAMETER SearchString
    Search string.
    .PARAMETER GraphApiVersion
    Graph version to call. The default version is "1.6".
    .EXAMPLE
    Get-UsersOrGroupsFromGraph -ObjectId "12345ba9-805f-43f8-98f7-34fa34aa51a7"
    Get user with user object Id "12345ba9-805f-43f8-98f7-34fa34aa51a7" from graph by calling graph service in version 1.6.
    .EXAMPLE
    Get-UsersOrGroupsFromGraph -SearchString "gfd"
    Get users who's UserPrincipalName starting with "gfd" from graph by calling graph service in version 1.6.
    #>
    [CmdletBinding(DefaultParameterSetName="Id")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Id")]
        [string]$ObjectId,

        [Parameter(Mandatory = $true, ParameterSetName = "Search")]
        [string]$SearchString,

        [Parameter(Mandatory = $false, ParameterSetName = "Search")]
        [Parameter(Mandatory = $false, ParameterSetName = "Id")]
        [string]$GraphApiVersion = "1.6"
    )

    Process
    {
        if (-not [string]::IsNullOrWhiteSpace($ObjectId))
        {
            $userGraphUri = "https://graph.windows.net/myorganization/users/{userId}`?&api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{userId}" -Value $ObjectId `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $userGraphResponse = InvokeApi -Route $userGraphUri -Method GET
            
            If($userGraphResponse.StatusCode -eq $null)
            {
                CreateUserObject -UserObj $userGraphResponse
            }

            $groupsGraphUri = "https://graph.windows.net/myorganization/groups/{groupId}`?api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{groupId}" -Value $ObjectId `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $groupGraphResponse = InvokeApi -Route $groupsGraphUri -Method GET

            If($groupGraphResponse.StatusCode -eq $null)
            {
                CreateGroupObject -GroupObj $groupGraphResponse
            }
        }
        else 
        {
            $userFilter = "startswith(userPrincipalName,'$SearchString') or startswith(displayName,'$SearchString')"
    
            $userGraphUri = "https://graph.windows.net/myorganization/users`?`$filter={filter}&api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{filter}" -Value $userFilter `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $userGraphResponse = InvokeApi -Route $userGraphUri -Method GET
    
            foreach($user in $userGraphResponse.value)
            {
                CreateUserObject -UserObj $user
            }

            $groupFilter = "startswith(displayName,'$SearchString')"
    
            $groupsGraphUri = "https://graph.windows.net/myorganization/groups`?`$filter={filter}&api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{filter}" -Value $groupFilter `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $groupsGraphResponse = InvokeApi -Route $groupsGraphUri -Method GET
    
            foreach($group in $groupsGraphResponse.value)
            {
                CreateGroupObject -GroupObj $group
            }    
        }
    }
}


function CreateUserObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$UserObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectType -Value $UserObj.objectType `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectId -Value $UserObj.objectId `
        | Add-Member -PassThru -MemberType NoteProperty -Name UserPrincipalName -Value $UserObj.userPrincipalName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Mail -Value $UserObj.mail `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $UserObj.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name AssignedLicenses -Value $UserObj.assignedLicenses `
        | Add-Member -PassThru -MemberType NoteProperty -Name AssignedPlans -Value $UserObj.assignedLicenses `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $UserObj;
}

function CreateGroupObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$GroupObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectType -Value $GroupObj.objectType `
        | Add-Member -PassThru -MemberType NoteProperty -Name Objectd -Value $GroupObj.objectId `
        | Add-Member -PassThru -MemberType NoteProperty -Name Mail -Value $GroupObj.mail `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $GroupObj.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $GroupObj;
}


function CreateTenantObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$TenantObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectType -Value $TenantObj.objectType `
        | Add-Member -PassThru -MemberType NoteProperty -Name TenantId -Value $TenantObj.objectId `
        | Add-Member -PassThru -MemberType NoteProperty -Name Country -Value $TenantObj.countryLetterCode `
        | Add-Member -PassThru -MemberType NoteProperty -Name Language -Value $TenantObj.preferredLanguage `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $TenantObj.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Domains -Value $TenantObj.verifiedDomains `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $TenantObj;
}
# SIG # Begin signature block
# MIIjeAYJKoZIhvcNAQcCoIIjaTCCI2UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDGYaVH7ncQCwtw
# 422DBXzEK246pI1AXPYOKzl0kSq2B6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVTTCCFUkCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBoDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgbb1V3hkC
# clky/AaDMaDtcwXSxRio2654wDC3FNgDvcYwNAYKKwYBBAGCNwIBDDEmMCSgEoAQ
# AFQAZQBzAHQAUwBpAGcAbqEOgAxodHRwOi8vdGVzdCAwDQYJKoZIhvcNAQEBBQAE
# ggEAATZ2DefAldmIfXogA+kargbzsLMyamps61HZlWh3chY6xzRdHRyhNS6m5yf9
# dtOGv+8axc6+5+pR6p2Xk7ZVgTKBzWhLzJ6G1inuHzskoyRJ0duoIttZl3+PlsRJ
# qfyfp0yGepEh6FJHMU9eEWeHTANu3mgErR5c3KhBfkCvSxN6L7+JpgX+yPE3lCKI
# uEDXPAU8MVLpJ5Q7jpad+qM1E9KaVzuTc2CBkDi9ZdzrsCvVBZcNCK5bEzPwrY2K
# oXwsM9c5lKH5FYOL/g1U+PKerTnqoC4Xa55ibjEP8syTNDamXYdmJ4/GIfiYaOuE
# XmbQV0SwPcLePUnD3q4QAl0GvKGCEuUwghLhBgorBgEEAYI3AwMBMYIS0TCCEs0G
# CSqGSIb3DQEHAqCCEr4wghK6AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsqhkiG
# 9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQC
# AQUABCD67ImNkaizZ9ns8h3cttH8Hw9eNEgw00Y6lZJfs2tKOAIGYInWSwzoGBMy
# MDIxMDUxMzE5MTc0NS42NDJaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3QkYxLUUzRUEt
# QjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCDjww
# ggTxMIID2aADAgECAhMzAAABUcNQ51lsqsanAAAAAAFRMA0GCSqGSIb3DQEBCwUA
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIwMTExMjE4MjYwNFoX
# DTIyMDIxMTE4MjYwNFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAk
# BgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEtRTNFQS1CODA4MSUwIwYDVQQDExxN
# aWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAn9KH76qErjvvOIkjWbHptMkYDjmG+JEmzguyr/VxjZgZ/ig8
# Mk47jqSJP5RxH/sDyqhYu7jPSO86siZh8u7DBX9L8I+AB+8fPPvD4uoLKD22BpoF
# l4B8Fw5K7SuibvbxGN7adL1/zW+sWXlVvpDhEPIKDICvEdNjGTLhktfftjefg9lu
# mBMUBJ2G4/g4ad0dDvRNmKiMZXXe/Ll4Qg/oPSzXCUEYoSSqa5D+5MRimVe5/YTL
# j0jVr8iF45V0hT7VH8OJO4YImcnZhq6Dw1G+w6ACRGePFmOWqW8tEZ13SMmOquJr
# Tkwyy8zyNtVttJAX7diFLbR0SvMlbJZWK0KHdwIDAQABo4IBGzCCARcwHQYDVR0O
# BBYEFMV3/+NoUGKTNGg6OMyE6fN1ROptMB8GA1UdIwQYMBaAFNVjOlyKMZDzQ3t8
# RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNy
# bDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggEBACv99cAVg5nx0SqjvLfQzmugMj5cJ9NE60duSH1LpxHYim9Ls3UfiYd7t0Jv
# yEw/rRTEKHbznV6LFLlX++lHJMGKzZnHtTe2OI6ZHFnNiFhtgyWuYDJrm7KQykNi
# 1G1LbuVie9MehmoK+hBiZnnrcfZSnBSokrvO2QEWHC1xnZ5wM82UEjprFYOkchU+
# 6RcoCjjmIFGfgSzNj1MIbf4lcJ5FoV1Mg6FwF45CijOXHVXrzkisMZ9puDpFjjEV
# 6TAY6INgMkhLev/AVow0sF8MfQztJIlFYdFEkZ5NF/IyzoC2Yb9iw4bCKdBrdD3A
# s6mvoGSNjCC6lOdz6EerJK3NhFgwggZxMIIEWaADAgECAgphCYEqAAAAAAACMA0G
# CSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3Jp
# dHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3
# PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMw
# VyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WETbijG
# GvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/
# 9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9
# pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGCNxUB
# BAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQBgjcU
# AgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8G
# A1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeG
# RWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jv
# b0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUH
# MAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQBgjcu
# AzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BLSS9k
# b2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwA
# XwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0B
# AQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkws8LF
# Zslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/XPle
# FzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO9sp6
# AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHOmWaQ
# jP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU9Mal
# CpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6YacR
# y5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdlR3jo
# +KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rIDVWZ
# eodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkqmqMR
# ZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN+w2/
# XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRKhggLOMIIC
# NwIBATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQG
# A1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4MDgxJTAjBgNVBAMTHE1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAKCir3Px
# P6RCCyVMJSAVoMV61yNeoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTAwDQYJKoZIhvcNAQEFBQACBQDkR3ILMCIYDzIwMjEwNTEzMTczODE5WhgP
# MjAyMTA1MTQxNzM4MTlaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAORHcgsCAQAw
# CgIBAAICCDkCAf8wBwIBAAICEVIwCgIFAORIw4sCAQAwNgYKKwYBBAGEWQoEAjEo
# MCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG
# 9w0BAQUFAAOBgQDcrXyLwqjYBmb72bBR/0LYLmmumMPWO6w0ZHP4x1B+kxDtqV5P
# MhtOFZmZVHefhA8B5/xBFis/Odh8mlzJ/Bbl3Jhz3jPfI1+e8CLP/+m/+oaWNJ4t
# vrDuALmQR1pjue3N0EhcYeBrcXjRNrEmknTqNU4gj5F9DGUot7XbisLZSDGCAw0w
# ggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABUcNQ
# 51lsqsanAAAAAAFRMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIAErhlIklNSbfA2e/2SiTIj8Jxp/
# BKziVPIX3/baWmUDMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgLs1cmYj4
# 1sFZBwCmFvv9ScP5tuuUhxsv/t0B9XF65UEwgZgwgYCkfjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAVHDUOdZbKrGpwAAAAABUTAiBCD0JEi/+SQK
# 63zGNuHSChp0/dKQLo5Qbvbp03518n7V6TANBgkqhkiG9w0BAQsFAASCAQB8FDVi
# BShyu7VnkR3sLYD5G9qkgET1M2ds+YaYDiN0tbKcuPmjhMoGJdQEuWixqMKc5iJ2
# saTmwnd8sNDSJJR6eq6lREzkH5V3WGkFV2KkIORkqHsQr18//MWSUNWVrGnSV6ja
# HtY7es0zvyFjNXm+dmuyS1Rv+KgWksAZZaDHc8nhgUelHYaMEV0uzTOo0SFtF18G
# PkNPxy1SAZtCjftHEFFYOlDBRMuTto6dWm3PpiwQrnHSoc40tuEvi/K4z+MTpQVf
# 7ZLDwy2PpmITBplXQQt2JEvgJK0XUqSUPwyiGcVOjsTttrTO9vaYydPK4smbZv8+
# zHRswOWzYB584Nk8
# SIG # End signature block
