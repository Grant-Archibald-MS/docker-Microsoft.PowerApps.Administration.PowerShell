# Overview

This repo contains a sample linux docker image for Microsoft.PowerApps.Administration.PowerShell with Azure Active Directoy device code authentication. This is not a complete implementation and would require further testing and updates to support authentication for different Power Platform resources.

## Getting Started

1. Build the docker image

```bash
docker build -t sample-microsoft.powerppps.administration.ps .
```

2. Run the image

```bash
docker run -it sample-microsoft.powerppps.administration.ps
```

3. Import the module

```powershell
Import-Module Microsoft.PowerApps.Administration.PowerShell
```

4. Run a Administration command e.g.

```powershell
Get-TenantSettings
```

5. Login using device code

## More Information

This sample uses the Microsoft.Identity.Client .Net Standard library to login and create OAuth AccessToken with the required resources.