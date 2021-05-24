FROM mcr.microsoft.com/dotnet/sdk as sdk
ADD Microsoft.PowerPlatform.Samples.Authentication.csproj /src/
ADD ActiveDirectoryAuth.cs /src/
RUN cd /src && dotnet publish --configuration release

FROM mcr.microsoft.com/powershell AS base
RUN pwsh -c "Invoke-WebRequest -Uri 'https://www.powershellgallery.com/api/v2/package/Microsoft.PowerApps.Administration.PowerShell/2.0.125' -OutFile '/opt/microsoft/powershell/7/Modules/Microsoft.PowerApps.Administration.PowerShell.zip'"
RUN pwsh -c "Expand-Archive /opt/microsoft/powershell/7/Modules/Microsoft.PowerApps.Administration.PowerShell.zip /opt/microsoft/powershell/7/Modules/Microsoft.PowerApps.Administration.PowerShell"
RUN rm /opt/microsoft/powershell/7/Modules/Microsoft.PowerApps.Administration.PowerShell/*.dll
RUN rm /opt/microsoft/powershell/7/Modules/Microsoft.PowerApps.Administration.PowerShell/*.psd1
RUN rm /opt/microsoft/powershell/7/Modules/Microsoft.PowerApps.Administration.PowerShell.zip
ADD Microsoft.PowerApps.AuthModule.psm1 /opt/microsoft/powershell/7/Modules/Microsoft.PowerApps.Administration.PowerShell/
COPY --from=sdk /src/bin/release/net5.0/publish/*.dll /opt/microsoft/powershell/7/Modules/Microsoft.PowerApps.Administration.PowerShell/