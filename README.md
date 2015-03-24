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

(If you don't want to build from source code, the compiled binaries can be downloaded from the [bin subfolder](./bin)).

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
You also need the certificate of the Certificate Authority (*CA*) for the MID servers, which can be downloaded from

* [http://aia.swissdigicert.ch/sdcs-root2.crt] (SHA1 thumbprint `77474fc630e40f4c47643f84bab8c6954a8a41ec`, SHA256 thumbprint `f09b122c7114f4a09bd4ea4f4a99d558b46e4c25cd81140d29c05613914c3841`)

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
  select `Certification Path`, the `Certificate stutus` should displays "This certificate is OK". Do not close the console now.

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

The Mobile ID Authentication Provider can be configured with a XML file.
In the alpha release, the file must be located in `C:\midadfs\MobileClient.xml` .
The content of the configuration file looks like

`````
<?xml version="1.0" encoding="utf-8" ?>
<mobileIdClient
  AP_ID="mid://dev.swisscom.ch"
  EnableSubscriberInfo = "True"
  SslKeystore = "LocalMachine"
  SslCertThumbprint ="59ade4238301c07b5064f7c33d57ca93895a2471"
  ServiceUrlPrefix ="https://soap.pp.mobileid.swisscom.com:8444/soap/services/"
  SslRootCaCertDN ="CN=Swisscom TEST Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch"
 />
`````
You need to specify the attribute values. The semantics of the attributes are

* `AP_ID`: Your Application Provider ID, as assigned by Mobile ID Service Provider. Mandatory.
* `EnableSubscriberInfo`: Whether to enable the Subscriber Info. If in doubt, set it to `false`.
* `SslKeystore`: Store location of certificate/key used for Mobile ID connectivity.
* `SslCertThumbprint`: The SHA1 Thumbprint of certificate used for Mobile ID connectivity. Mandatory.
* `ServiceUrlPrefix`: URL for Mobile ID service.
* `SslRootCaCertDN`: Distinguished Name of the Root Certificate in the certificate chain of Mobile ID servers

Notes:
* Changes in `MobileClient.xml` take effect only after the ADFS service has been restarted.


### Step 3: Installation of Mobile ID Authentication Provider for ADFS

1. Download (or build) the `MobileId.Adfs.AuthnAdapter.dll`, for example to `C:\midadfs`.

2. Install the DLL into Global Assembly Cache (GAC): Open a Windows PowerShell prompt, enters
`````
Set-location "C:\midadfs"
[System.Reflection.Assembly]::Load("System.EnterpriseServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
$publish = New-Object System.EnterpriseServices.Internal.Publish
$publish.GacInstall("C:\midadfs\ADFS-MobileID.dll")
`````
Alternatively, you can also install the DLL with command `gacutil.exe /i MobileId.Adfs.AuthnAdapter.dll`. 
(`gacutil.exe` is available in Visual Studio 2013, default location `C:\Program Files (x86)\Microsoft SDKs\Windows\v8.1A\bin\NETFX 4.5.1 Tools`.)

3. Register the DLL with ADFS: In Windows PowerShell prompt, enters
`````
$TypeName = "MobileId.Adfs.AuthenticationAdapter, MobileId.Adfs.AuthnAdapter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=2d8af5277000f5f0, processorArchitecture=MSIL"
Register-AdfsAuthenticationProvider -TypeName $TypeName -Name "MobileID"
`````
Note: If you build the DLL from source, you should have a different `PublicKeyToken` value. You need to modify the value `PublicKeyToken` in the command above.

4. Restart the ADFS service

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

## Operational Task: Mapping of user attributes

Mobile ID authentication provider need to retrieve the mobile ID of the user once the user has been identified with the primary authentication.
The current release relies on the following LDAP attributes in Active Directory:

* `userPrincipleName`:	this is the username that the user authenticates with the primary authentication. Example: `tester1@contoso.com`
* `mobile`:	a telephone number to which the Mobile ID authentication message will be sent to. Example: `+41791234567`

For Mobile ID authentication, both attributes must be defined.

## Uninstallation of the binaries

1. Ungister the Mobile ID Authentication Provider from ADFS: In Windows PowerShell prompt, enters
`````
Unregister-AdfsAuthenticationProvider MobileID
`````

2. Restart ADFS service.

3. Remove DLL from GAC:

TODO: PowerShell cmdlet

If `gacutil.exe` is available in your runtime environment, you can also remove DLL from GAC with `gacutil.exe /u MobileId.Adfs.AuthnAdapter` .

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
        Active Directory Federation Services (AD FS) installed. By default, the DLL file is located in
	`C:\Windows\ADFS` on your server. 
        The DLL file should be copied to the folder of the project `AuthnAdapter`. In the example above, it is `H:\midadfs\AuthnAdapter`.

3.	Create your own assembly-signing key `mobileid.snk`, either in visual studio (right-click a project > `Properties` > `Signing` > `Sign the assembly` > create new key), or with command line (`sn.exe -k 2048 mobileid.snk`).
	Place it in the folder where the *.sln file is located (`H:\midadfs` in the example).

The solution should be ready to build now. Each project folder has a README file which briefly describes the project. The target audience is developer.

__END__