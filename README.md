# Mobile ID Authentication Provider for Active Directory Federation Service (ADFS)

*Alpha Release*

This is an Active Directory Federation Service (ADFS) external authentication provider
which authenticates end users with [Mobile ID](https://www.swisscom.ch/mid).

The current document is a destilled version of [Microsoft ADFS Integration Guide (work in progress)](https://www.swisscom.ch/en/business/mobile-id/technical-details/technical-documents.html).
If you are familiar with the contents in Integration Guide, you can skip the rest of this document.

## System Requirement 

### Runtime Environment:

* Microsoft Windows Server 2012 R2
* You have a Mobile ID Application Provider Account (`AP_ID`)

### Build Environment:

(If you don't want to build from source code, the compiled binaries can be downloaded from the [binaries subfolder](./binaries)).

* Microsoft Visual Studio 2013 (which includes Microsoft .NET Framework 4.5.1)
* The file Microsoft.IdentityServer.Web.dll. The DLL file can be copied from a Microsoft Windows Server 2012 R2 server.

## Installation of the Runtime Environment:

### Step 0: Installation of ADFS service

This depends strongly on the purpose of the environment: development lab, integration test, highly available proudction.
Microsoft has provided a [walkthrough guide](https://technet.microsoft.com/en-us/library/dn280939.aspx "Set up the lab environment for AD FS in Windows Server 2012 R2") for development lab.

### Step 1: Establishment of Connectivity between ADFS server(s) and Mobile ID servers

#### 1.1: IP connectivity between Mobile ID client and Mobile ID server

ADFS servers can access the Mobile ID servers (*MID*) only from specific IP addresses.
The address range is specific to an Application Provider (*AP*) and configured by the MID service during the enrollment process for the AP.

#### 1.2. SSL connectivity between Mobile ID client and Mobile ID server

An ADFS server must establish a mutually authenticated SSL/TLS connection with a MID server before calling the MID services.
During the enrollment process of Mobile ID Application Provider Account, you have created a SSL/TLS client certificate for 
your Mobile ID connection. It is recommend not to re-use the existing certificate/keys of ADFS service.
You also need the certificate of the Certificate Authority (*CA*) for the MID servers, which is located in [certs](../certs) folder.

##### Configuration for SSL/TLS:

1.2.1. Import your SSL client certificate file (PFX/PKCS#12 format) into *computer* certificate store:

  Right-click your SSL Client certificate file, select `Install PFX`, the Certificate Import Wizard will pop up.
  Select `Local Machine` as Store Location, Click `Next` twice, then enter the passphase of the PFX file, 
  click `Next` and click `Finish`.

1.2.2. If your SSL client certificate is issued by a Certificate Authority trusted by your organisation, you
  can skip this step, otherwise (e.g. self-signed certificate), you need explicitly configure trust for it:
  Run `mmc.exe`, navigate to `File` > `Add/Remove Snap-in...`, select `Certificates` in left `Available snap-ins` panel, click `Add >`,
  choose `Computer account`, click `Next`, `Finish`, `OK`, the `Certicates (Local Computer)` snap-in is added to Management Console.

  In the Certificate Management Console for Local Computer;
  right-click `Trusted People`, navigate to `All Task`, then `Import...`, this opens the `Certificate Import Wizard`;
  Clicks `Next`, locates the PFX file in `File to Import`, `Next`, enters passphrase for the private key, clicks `Next` twice and `Finish`.

  Make sure that the service account of ADFS role service has access to the imported key/certificate.

1.2.3. Verify the SSL client certificate has been correctly imported and trusted:

  In Certificate Management Console (`certmgr.msc`), navigate to Personal > Certificates, double-click the certificate imported in step 1, 
  select `Certification Path`, the `Certificate status` should displays "This certificate is OK". Do not close the console now.

1.2.4. Configure trust to Root CA of MID servers:
   In the open console, navigate to `Trusted Root Certificate Authority`,
   Right-click `Certificates`, select `All Tasks`, `Import...` , then `Next`,
   select the file *.crt containing the Root CA of MID servers in the correct environment (production/test),
   `Next` twice, `Finish`, confirm `Yes` on the Security Warning "You are about to install a certificate from a certificate authority (CA) claiming to represent: ... Thumbprint (sha1): ..."
   Click `OK`.

1.2.5. Verify the SSL/TLS connectivity:
   Use "Internet Explorer" (version 10 & 11 are tested) to connect to the URL
   https://mobileid.swisscom.com/soap/services/MSS_ProfilePort.
   IE should display a `Confirm Certificate` dialog for picking up the client certificate and then the text

`````
   MSS_ProfilePort
   Hi there, ...
`````

### Step 2: Configuration of Mobile ID Authentication Provider

The Mobile ID Authentication Provider can be configured with a XML file, e.g. `C:\midadfs\MobileId.Adfs.AuthnAdapter.xml`.
The folder [samples](samples) contain several examples. The content of the configuration file looks like

`````
<?xml version="1.0" encoding="utf-8" ?>
<appConfig>
<mobileIdClient
  AP_ID="mid://dev.swisscom.ch"
  SslKeystore = "LocalMachine"
  SslCertThumbprint ="59ade4238301c07b5064f7c33d57ca93895a2471"
// TODO: ServicePromptPrefix
/>
<mobileIdAdfs
  DefaultLoginPrompt = "Login with Mobile ID to ADFS (code: {0}) ?"
/>
</appConfig>
`````
The configuration contains two elements. The element `mobileIdClient` specifies the Mobild ID Service
while the element `mobileIdAdfs` the integration of Mobile ID with ADFS. The semantics of the attributes are:

* Element `mobileIdClient`:
  + `AP_ID`: Your Application Provider ID, as assigned by Mobile ID Service Provider. Mandatory.
  + `EnableSubscriberInfo`: Whether to enable the Subscriber Info. Default: `false`
  + `ServiceUrlPrefix`: URL for Mobile ID service, must end with `/`. Default: `https://mobileid.swisscom.com/soap/services/`
  + `SslKeystore`: Store location of certificate/key used for Mobile ID connectivity. For ADFS, the value should be usually `LocalMachine`. Default: `CurrentUser`
  + `SslCertThumbprint`: The SHA1 Thumbprint of certificate used for Mobile ID connectivity. The thumbprint can be read out of the `Certificate` GUI (i.e. double-click the certificate file), or with a PowerShell cmdlet like `Get-ChildItem -Path cert:\\LocalMachine\My`. Mandatory.
  + `SslRootCaCertDN`: Distinguished Name of the Root Certificate in the certificate chain of Mobile ID servers. Default: "CN=Swisscom Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch"
* Element `mobileIdAdfs`:
  + `AdAttrMobile`: Attribute name of AD user object for the mobile number. The attribute should have exactly one value. Default: `mobile`.
  + `AdAttrSerialNumber`: Attribute name of AD user object for the Serial Number of Mobile ID. The attribute should have at most one value. Default: `msNPCallingStationID`
  + `DefaultLoginPrompt`: Default login message sent to the mobile phone.
     The string can optionally contains one place holder `{0}` which expands to a 5-char random string.
     Default: `"Login with Mobile ID ({0})?"`
  + `LoginNonceLength`: Length of the random string to be included in the login prompt (see parameter `DefaultLoginPrompt`). Default: 5
  + `SessionMaxTries`:  In an *Mobile ID authentication session", a user can retry the Mobile ID after an unsuccessful login. This is the maximum number of unsucessful login tries in a Mobile ID authentication session. Default: `5`.
  + `SessionTimeoutSeconds`: Maximum duration, in seconds, of a Mobile ID authentication session.
  + `ShowDebugMsg`: If this parameter is `true`, debugging information may be displayed in web browser in case of errors. Otherwise the debugging information is not displayed. (TODO: not yet implmented in alpha release.) Default: `false` 

### Step 3: Installation of Mobile ID Authentication Provider for ADFS

1. Download (or build) the `MobileId.Adfs.AuthnAdapter.dll`, for example to `C:\midadfs`.

2. Install the DLL into Global Assembly Cache (GAC): Open a Windows PowerShell prompt, enters
   `````
   Set-location "C:\midadfs"
   [System.Reflection.Assembly]::Load("System.EnterpriseServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
   $publish = New-Object System.EnterpriseServices.Internal.Publish
   $publish.GacInstall("C:\midadfs\MobileId.Adfs.AuthnAdapter.dll")
   `````
   Alternatively, you can also install the DLL with command `gacutil.exe /i MobileId.Adfs.AuthnAdapter.dll`. 
   (`gacutil.exe` is available in Visual Studio 2013, default location `C:\Program Files (x86)\Microsoft SDKs\Windows\v8.1A\bin\NETFX 4.5.1 Tools`.)

3. Register the DLL with ADFS: Take a note of the version of `MobileId.Adfs.AuthenticationAdapter.dll` (right-click the DLL file in Windows Explorer, select `Properties`, `Details`, read `File Version`). In the example below, we assume it is `1.0.0.1`. In Windows PowerShell prompt, enters
   `````
   $TypeName = "MobileId.Adfs.AuthenticationAdapter, MobileId.Adfs.AuthnAdapter, Version=1.0.0.1, Culture=neutral, PublicKeyToken=2d8af5277000f5f0, processorArchitecture=MSIL"
   Register-AdfsAuthenticationProvider -ConfigurationFilePath "C:\midadfs\MobileId.Adfs.AuthnAdapter.xml" -TypeName $TypeName -Name "MobileID"
   `````
   Notes: 
   * If you build the DLL from source, you may have a different `PublicKeyToken` value. In this case, you need to modify the value `PublicKeyToken` in the command above.
   * If the DLL has a different value, you need to replace the value of `Version`.

4. Install static web resources (`C:\midadfs\spin.min.js` in this example) into ADFS: In Windows PowerShell prompt, enters
   `````
   New-AdfsWebTheme -Name custom -SourceName default
   Set-AdfsWebTheme -TargetName custom -AdditionalFileResource @{Uri="/adfs/portal/script/spin.js";path="C:\midadfs\spin.min.js"}
   Set-AdfsWebConfig -ActiveThemeName custom
   `````

5. Restart the `Active Directory Federation Services`, e.g. in command line prompt
   `````
   net stop adfsSrv
   net start adfsSrv
   `````

### Step 4: Configuration of ADFS

This depends on your use case. For the verification purpose, configure ADFS as follows:

1. Open the `AD FS Management Console`:
   start `Server Manager`, select `Tools`, `AD FS Management`.

2. In `Authentication Policies`, edit `Global Authentication Policy`.
   For Primary Authentication, enable `Form Authentication` for `Extranet` and `Intranet` but do not enable `device authentication`.
   For Multi-faction Authentication, require MFA for both `Intranet`and `Extranet`, select 'Mobile ID Authentation' as `additional authentication method`.

3. TODO: Make sure that the service account of ADFS have access to the certificate/key used by Mobile ID (step 1.2.2).

### Step 5: Verification

You can verify the installation by login to the ADFS login web page with a test user.

Assuming you have done the user mapping (see ) for the test user, you can connect your web browser
`https://<your.adfs.server.dns>/adfs/ls/IdpInitiatedSignon.aspx`. 
After login with <user>@<domain> / password, Mobile ID login should occur.

## Operational Tasks

### Mapping of user attributes

Mobile ID authentication provider need to retrieve the mobile ID of the user once the user has been identified with the primary authentication.
The current release relies on the following LDAP attributes in Active Directory:

* `userPrincipleName`:	this is the username that the user authenticates with the primary authentication. Example: `tester1@contoso.com`
* `mobile`:	a telephone number to which the Mobile ID authentication message will be sent to. Example: `+41791234567`

For Mobile ID authentication, both attributes must be defined.

### Configuration change

If you have modified a configuration file, say `C:\midadfs\MobileId.Adfs.AuthnAdapter.xml`, after installation,
you need re-import the config file into ADFS with PowerShell and restart the and restart the `Active Directory Federation Services`:
`````
Import-AdfsAuthenticationProviderConfigurationData -FilePath "C:\midadfs\MobileId.Adfs.AuthnAdapter.xml" -Name "MobileID"
Restart-Service adfsSrv
`````

## Uninstallation of the binaries

1. In ADFS Management Console, unselect `Mobile ID Authentication` from any configured Multi-factor authentications.

2. Unregister the Mobile ID Authentication Provider from ADFS: In Windows PowerShell prompt, enter
   `Unregister-AdfsAuthenticationProvider MobileID`

3. Restart ADFS service.

4. Remove the DLL of Mobile ID Authentication Provider from GAC:
   If `gacutil.exe` is available in your runtime environment, you can also remove the DLL from GAC with `gacutil.exe /u MobileId.Adfs.AuthnAdapter` .
   TODO: PowerShell cmdlet

Notes:
* Configuration file and log files are not touched by the uninstallation.

## Upgrade

Unless otherwise specified, an binary upgrade is an uninstallation of the binaries, followed by
the installation of Mobile ID Authentication Provider (step 3).

## Troubleshooting

### Trace files

The logging / tracing of Mobile ID Authentication Provider can be controlled via the dotNet tracing
configuration mechanism. The configuration file is shared with configuration file ADFS service, 
which is located in `C:\Windows\ADFS\Microsoft.IdentityServer.ServiceHost.exe.config`.
Mobile ID Authentication Provider writes tracing messages to `MobileId.WebClient` and `MobileId.Adfs.AuthnAdapter`.
You can modify the configuration file to enable / adjust tracing messages of Mobile ID Authentication Provider.

The sample configuration segment write all tracing messages to Windows Event Log and the files 
`C:\midadfs\MobileIdClient.log`, `C:\midadfs\MobileIdAdfs.log`.

`````
...
<system.diagnostics>
  <switches>
    <!--  The next setting specifies the "global" logging severity threshold. In order of decreasing verbosity,
          the value can be one of "All", "Verbose", "Information", "Warning", "Error", "Critical", "None".
    -->
    <add name="MobileId.WebClient.TraceSeverity" value="All"/>
    <add name="MobileId.Adfs.TraceSeverity" value="All"/>
  </switches>

  <sources>
    ...
    <source name="MobileId.WebClient" switchName="MobileId.WebClient.TraceSeverity" switchType="System.Diagnostics.SourceSwitch">
      <listeners>
        <remove name="Default"/>
        <!-- This listener writes to Windows Event Log (Log=Application, EventSource="MobileID") -->
        <add name="eventLog" type="System.Diagnostics.EventLogTraceListener" initializeData="MobileID">
          <filter type="System.Diagnostics.EventTypeFilter" initializeData="Information" />
        </add>
        <!-- This listeners appends to a file for debugging purpose -->
        <add name="logfile" type="System.Diagnostics.TextWriterTraceListener" initializeData="C:\midadfs\MobileIdClient.log">
          <filter type="System.Diagnostics.EventTypeFilter" initializeData="All"/>
        </add>
      </listeners>
    </source>
    <source name="MobileId.Adfs.AuthnAdapter" switchName="MobileId.Adfs.TraceSeverity" switchType="System.Diagnostics.SourceSwitch">
      <listeners>
        <remove name="Default"/>
        <!-- This listener writes to Windows Event Log (Log=Application, EventSource="MobileID.Adfs") -->
        <add name="eventLog" type="System.Diagnostics.EventLogTraceListener" initializeData="MobileID.Adfs">
          <filter type="System.Diagnostics.EventTypeFilter" initializeData="Information" />
        </add>
        <!-- This listens appends to a file for debugging purpose -->
        <add name="logfile" type="System.Diagnostics.TextWriterTraceListener" traceOutputOptions="ProcessId,ThreadId,DateTime" initializeData="C:\midadfs\MobileIdAdfs.log">
          <filter type="System.Diagnostics.EventTypeFilter" initializeData="All"/>
        </add>
      </listeners>
    </source>
  </sources>
  <trace autoflush="true" indentsize="2"></trace>
</system.diagnostics>

`````

## Installation of the Build Environment:

1.	Check out the source code from here to your development PC, for example, folder `H:\midadfs` (subfolders are `Service` and `AuthnAdapter`).

2.	Copy the file Microsoft.IdentityServer.Web.dll from a Windows 2012 R2 server which has the role 
        `Active Directory Federation Services` (AD FS) installed. By default, the DLL file is located in
	`C:\Windows\ADFS` on your server. 
        The DLL file should be copied to the folder of the project `AuthnAdapter`. In the example above, it is `H:\midadfs\AuthnAdapter`.

3.	Create your own assembly-signing key `mobileid.snk`, either in visual studio (right-click a project > `Properties` > `Signing` > `Sign the assembly` > create new key), or with command line (`sn.exe -k 2048 mobileid.snk`).
	Place it in the folder where the *.sln file is located (`H:\midadfs` in the example).

The solution should be ready to build now. Each project folder has a README file which briefly describes the project. The target audience is developer.

# Known Issues

* HTTP Proxy between Mobile ID Servers and ADFS Server(s): currently untested.

__END__
