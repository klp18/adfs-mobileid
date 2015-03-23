using Microsoft.IdentityServer.Web.Authentication.External;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace MobileId.Adfs
{
    public class AuthenticationAdapter : IAuthenticationAdapter
    {
        private static TraceSource logger = new TraceSource("MobileId.Adfs.AuthnAdapter");
        private static string version = "1.03";

        // keys for data to be transferred via Context
        private const string MSISDN = "msisdn";  // Mobile ID Number to place the signature request
        private const string UKEYSN = "userSN";  // serial number of user's keypair, retrieved from SerialNumber of the DN of user cert
        private const string USERUPN = "userUPN"; // User Principal Name of the first authentication method, needed by TryEndAuthentication(...) for audit/logging
        private const string MSSPTRXID = "mTrxId"; // Transaction ID returned by authentication server (MSSP)
        private const string AUTHTBEGIN = "authBegin"; // timestamp when sending MSS_SignatureReq
        private const string DTBS = "dtbs";

        // objects re-used among authentication "sessions"
        private WebClientConfig cfg = null;
        private IAuthentication _webClient = null;

        // statistics, also used for recycle_webClient
        private ulong reqCount = 0;
        private ulong webClientMaxRequest = 100;    // maximum number of requests a webClient can process. TODO: move to cfg
        // TODO: max lifetime of a webClient;

        // load dependent assemblies from embedded resource
        // private readonly static LoadDependencies _loadDependencies = new LoadDependencies();

        // EventLog
        // TODO: Should go into "Applications and Services Logs / AD FS / MobileID (or the existing Admin in AD FS)
        private const string EVENTLOGSource = "AD FS MobileID";
        private const string EVENTLOGGroup = "Application";

        private IAuthentication getWebClient()
        {
            if (_webClient == null || (++reqCount % webClientMaxRequest) == 0) {
                if (_webClient != null)
                    logger.TraceEvent(TraceEventType.Verbose, 0, "delObj: name=WebClientImpl, reason=MaxRequest, id="
                        + System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(_webClient));
                    // see http://stackoverflow.com/questions/5703993/how-to-print-object-id
                _webClient = new WebClientImpl(cfg);
                logger.TraceEvent(TraceEventType.Verbose, 0, "newObj: name=WebClientImpl, id="
                    + System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(_webClient));
            } else {
                // TODO: check lifetime, recycle _webClient on time-to-live
            };
            return _webClient;
        }

        private string _str(IAuthenticationContext ctx)
        {
            if (ctx == null)
                return "null";
            StringBuilder sb = new StringBuilder();
            sb.Append("{Data: {");
            foreach (var entry in ctx.Data)
                sb.Append("\"").Append(entry.Key).Append("\":\"").Append(entry.Value).Append("\", ");
            sb.Append("}, Lcid: ").Append(ctx.Lcid);
            sb.Append(", ActivityId: \"").Append(ctx.ActivityId);
            sb.Append("\", ContextId: \"").Append(ctx.ContextId);
            sb.Append("\", obj=").Append(System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(ctx));
            sb.Append("}");
            return sb.ToString();
        }

        private string _str(Claim c)
        {
            if (c == null) return "null";
            StringBuilder sb = new StringBuilder();
            sb.Append("{");
            ClaimsIdentity subj = c.Subject;
            if (subj == null) {
                sb.Append("Subject: null; ");
            } else {
                sb.Append("Subject: {");
                sb.Append("Name: \"").Append(subj.Name).Append("\"; ");
                sb.Append("Label: \"").Append(subj.Label).Append("\"; ");
                sb.Append("AuthenticationType: \"").Append(subj.AuthenticationType).Append("\"; ");
                sb.Append("IsAuthenticated: ").Append(subj.IsAuthenticated).Append("; " );
                sb.Append("Actor={").Append(subj.Actor).Append("}; ");
                sb.Append("}, ");
            };
            if (c.Value == null) {
                sb.Append("Value: null;");
            } else {
                sb.Append("Value: \"").Append(c.Value).Append("\"; ");
            };
            if (c.Issuer == null) {
                sb.Append("Issuer: null;");
            } else {
                sb.Append("Issuer: \"").Append(c.Issuer).Append("\"; ");
            };
            sb.Append("Properties: ").Append(_str(c.Properties));
            return sb.ToString();
        }

        private string _str(IDictionary<string,string> dict)
        {
            if (dict == null) return "Null";
            StringBuilder sb = new StringBuilder();
            sb.Append("{");
            foreach (KeyValuePair<string, string> e in dict)
            {
                sb.Append("\"").Append(e.Key).Append("\": \"").Append(e.Value).Append("\", ");
            }
            sb.Append("}");
            return sb.ToString();
        }

        private string _str(System.Collections.Specialized.NameValueCollection c)
        {
            if (c == null) return "null";
            StringBuilder sb = new StringBuilder();
            sb.Append("{");
            foreach (string k in c) 
                sb.Append(k).Append(": \"").Append(c[k]).Append("\",");
            sb.Append("}");
            return sb.ToString();
        }

        private string _str(HttpListenerRequest req) {
            if (req == null) return "null";
            StringBuilder sb = new StringBuilder();
            sb.Append("{RawUrl:\"").Append(req.RawUrl).Append("\"; ");
            sb.Append("QueryString:").Append(_str(req.QueryString)).Append("; ");
            //CookieCollection cookies = req.Cookies;
            //if (cookies == null) {
            //    sb.Append("Cookies:null; ");
            //} else {
            //    sb.Append("Cookies:\"").Append(cookies).Append("\"; ");  // TODO
            //};
            sb.Append("}");
            return sb.ToString();

        }

        private string _str(IProofData o)
        {
            if (o == null) return "null";
            StringBuilder sb = new StringBuilder();
            sb.Append("{");
            foreach (KeyValuePair<string, object> pair in o.Properties)
                sb.Append(pair.Key).Append(":\"").Append(pair.Value).Append("\"; ");
            sb.Append("}");
            return sb.ToString();
        }

        // Check if adapter available for the user
        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext ctx)
        {
            logger.TraceEvent(TraceEventType.Verbose, 0, "IsAvailableForUser(claim=" + _str(identityClaim) + ", ctx=" + _str(ctx) + ")");

            string upn = identityClaim.Value; // UPN Claim from the mandatory Primary Authentication
            string msisdn = null;
            string snOfDN = null;

            // Define the user properties to load
            // TODO: attributes should be configurable
            string propertyMSISDN = "mobile";
            string propertySNofDN = "msNPCallingStationID";

            // Search for the user
            try
            {
                // TODO: optional credentials for DirectoryEntry needed ?  I.E. LDAP instead of AD
                using (DirectoryEntry entry = new DirectoryEntry())
                {
                    DirectorySearcher ds = new DirectorySearcher(entry);
                    ds.SearchScope = SearchScope.Subtree;
                    ds.Filter = "(&(objectClass=user)(objectCategory=person)(userPrincipalName=" + upn + "))";
                    ds.PropertiesToLoad.Add(propertyMSISDN);
                    ds.PropertiesToLoad.Add(propertySNofDN);
                    // TODO: performance optimization retrieve only needed attributes
                    // TODO: error handling for the case that required attributes are not available in AD
                    SearchResult result = ds.FindOne();
                    if (result != null)
                    {
                        // Get the properties
                        ResultPropertyCollection propertyCollection = result.Properties;
                        // Process all properties
                        foreach (string thisProperty in propertyCollection.PropertyNames)
                        {
                            // Process all property values
                            foreach (string propertyValue in propertyCollection[thisProperty])
                            {
                                // Get the proper value (the attribute may change it's name, better to compare in lowercase)
                                if (thisProperty.ToLower() == propertyMSISDN.ToLower())
                                {
                                    msisdn = propertyValue.ToString();
                                    ctx.Data.Add(MSISDN, propertyValue.ToString());
                                }
                                if (thisProperty.ToLower() == propertySNofDN.ToLower())
                                {
                                    snOfDN = propertyValue.ToString();
                                    ctx.Data.Add(UKEYSN, propertyValue.ToString());
                                }
                            }
                        }
                        EventLog.WriteEntry(EVENTLOGSource, "Found user " + upn + " using " + ds.Filter +
                            " with properties " + propertyMSISDN + "=" + msisdn + "," + propertySNofDN + "=" + snOfDN);
                    }
                    else
                    {
                        EventLog.WriteEntry(EVENTLOGSource, "User not found " + upn + " using " + ds.Filter, EventLogEntryType.Error, 102);
                    }
                    ds.Dispose();
                }
            }
            catch (Exception ex)
            {
                logger.TraceEvent(TraceEventType.Error, 0, "AD Search Error: " + ex.Message);
                return false;
            }

            if (String.IsNullOrEmpty(msisdn))
            {
                EventLog.WriteEntry(EVENTLOGSource, "Method not available for user " + upn + " (no MSISN defined)", EventLogEntryType.Error, 102);
                logger.TraceEvent(TraceEventType.Warning, 0, "Mobile ID not available for " + upn + ": mobile attribute not found in AD");
                return false;
            }

            // store "session"-scope information to ctx
            ctx.Data.Add(USERUPN, upn);
            ctx.Data.Add(UKEYSN, snOfDN);
            return true;
        }

        // Authentication starts here, UPN of primary login is passed as Claim. Called once per ADFS-login-session.
        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest reqHttp, IAuthenticationContext ctx)
        {
            logger.TraceEvent(TraceEventType.Verbose, 0, "BeginAuthentication(claim=" + _str(identityClaim) + ", req=" + _str(reqHttp) + ", ctx=" + _str(ctx) + ")");

            // int userLang = ctx.Lcid;

            // Start the asynchrous login
            AuthRequestDto req = new AuthRequestDto();
            req.PhoneNumber = (string) ctx.Data[MSISDN];
            req.DataToBeSigned = "AP.TEST.Login: Hi ADFS";  // TODO: language dependent string, generate nonce
            AuthResponseDto rsp = getWebClient().RequestSignature(req, true /* async */); 

            // TODO: check response status. signature maybe already available, error (e.g. no connection) may also occur

            ctx.Data.Add(MSSPTRXID, rsp.MsspTransId);
            ctx.Data.Add(DTBS, req.DataToBeSigned);
            ctx.Data.Add(AUTHTBEGIN, DateTime.UtcNow.Ticks);

            return new AdapterPresentation(AuthView.SignRequestSent, req.PhoneNumber);
        }

        public IAuthenticationAdapterMetadata Metadata
        {
            get { return new AuthenticationAdapterMetadata(); }
        }

        // Called when the authentication provider is loaded by AD FS into it's pipeline.
        // This is where AD FS passes us the config data as a Stream, if such data was supplied at registration of the adapter
        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            logger.TraceEvent(TraceEventType.Verbose, 0, "OnAuthenticationPipelineLoad(verAdapter={0}, cfg={1}), obj={2})",
                version, configData.Data, System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(this));

            if (cfg == null) {
                string cfgFileName = "C:\\midadfs\\MobileIdClient.xml";
                cfg = WebClientConfig.CreateConfigFromFile(cfgFileName); // TODO: read from configData
                logger.TraceData(TraceEventType.Verbose, 0, "READ_CONFIG: file=" + cfgFileName); 
            }

            
            // AuditLog: log provider name and version
            // Verify EventLog Source
            // TODO: CreateEventSource fails if caller has no enough rights. Add error handling and avoid EventLog.WriteEntry if not present
            if (!EventLog.SourceExists(EVENTLOGSource))
                EventLog.CreateEventSource(EVENTLOGSource, EVENTLOGGroup);
            EventLog.WriteEntry(EVENTLOGSource, "Adapter loaded", EventLogEntryType.Information, 900);

            if (!EventLog.SourceExists("MobileId.Client"))
                EventLog.CreateEventSource("MobileId.Client","Application");

            if (!EventLog.SourceExists("MobileId.Adfs"))
                EventLog.CreateEventSource("MobileId.Adfs", "Application");
        }

        // Called whenever the authentication provider is unloaded fro the AD FS pipeline.
        public void OnAuthenticationPipelineUnload()
        {
            logger.TraceEvent(TraceEventType.Verbose, 0, "OnAuthenticationPipelineUnload(obj={0})",
                System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(this));
            EventLog.WriteEntry(EVENTLOGSource, "Adapter unloaded", EventLogEntryType.Information, 901);
        }

        // Handle the errors during the authentication process during BeginAuthentication or TryEndAuthentication
        public IAdapterPresentation OnError(System.Net.HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            logger.TraceData(TraceEventType.Error, 0, ex);
            return new AdapterPresentation(AuthView.AuthError, ex.Message);
        }

        // Authentication should perform the actual authentication and return at least one Claim on success.
        // proofData contains a dictionnary of strings to objects that have been asked in the BeginAuthentication
        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext ctx, IProofData proofData, System.Net.HttpListenerRequest request, out Claim[] claims)
        {
            logger.TraceEvent(TraceEventType.Verbose, 0, "TryEndAuthentication(ctx=" + _str(ctx) + ", prf=" + _str(proofData) + ", req=" + _str(request));

            string formAction = (string) proofData.Properties["Action"];
            string upn = (string)ctx.Data[USERUPN];
            string msspTransId = (string)ctx.Data[MSSPTRXID];
            if (msspTransId == null)
                throw new ExternalAuthenticationException("Internal Error: user=" + upn + ". No MSSP TransID", ctx);

            claims = null;
            if (formAction == "Continue")
            {
                // TODO: check session age, i.e. timespan(Now, authBegin)

                AuthRequestDto req = new AuthRequestDto();
                req.PhoneNumber = (string)ctx.Data[MSISDN];
                req.DataToBeSigned = (string)ctx.Data[DTBS];

                AuthResponseDto rsp;
                for (int i = 15; i <= 80; i++) {
                    rsp = getWebClient().PollSignature(req, msspTransId);
                    if (rsp.Status.Code == ServiceStatusCode.SIGNATURE)
                    {
                        // TODO: verify rsp & extract info  ( + ", sn=" + ctx.Data[UKEYSN])
                        // TODO: Check if the SNofDN is the same
                        logger.TraceEvent(TraceEventType.Information, 0, "AUTHN_OK: upn=" + upn + ", msspTransId=" + msspTransId + ", i=" + i);
                        claims = new System.Security.Claims.Claim[] { 
                            new System.Security.Claims.Claim(
                            "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
                            "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/hardwaretoken")
                        };
                        EventLog.WriteEntry(EVENTLOGSource, "Authentication success for " + upn, EventLogEntryType.SuccessAudit, 100);
                        return null;
                    }
                    else if (rsp.Status.Code == ServiceStatusCode.OUSTANDING_TRANSACTION)
                    {
                        logger.TraceEvent(TraceEventType.Verbose, 0, "AUTHN_PENDING: upn=" + upn + ", msspTransId=" + msspTransId + ", i=" + i);
                        System.Threading.Thread.Sleep(1000);
                    }
                    else
                    {
                        logger.TraceEvent(TraceEventType.Error, 0, "TECH_ERROR: msspTransId=" + msspTransId + ", srvStatusCode=" + rsp.Status.Code + ", srvStatusMsg=" +rsp.Status.Message);
                        return new AdapterPresentation(AuthView.AuthError, rsp.Status, (string) rsp.Detail);
                    }
                }

            }

            // Handle Cancel
            if (formAction == "Cancel")
            {
                //EventLog.WriteEntry(EventLogSource, "Authentication cancelled for " + this.upn, EventLogEntryType.Warning, 102);
                //claims = null;
                //return new AdapterPresentation(2, this.msspTransId, "Authentication cancelled.");
                throw new NotImplementedException("formAction 'Abort'");
            }

            // Handle Abort
            if (formAction == "Abort")
            {
                //// TODO: Abort should go back to the Primary Authentication and/or abort the entire process instead of displaying 'Abort' again
                //EventLog.WriteEntry(EventLogSource, "Authentication failed for " + this.upn, EventLogEntryType.Warning, 101);
                //claims = null;
                //return new AdapterPresentation(9, this.msspTransId, "Authentication failed.");
                throw new NotImplementedException("formAction 'Abort'");
            }

            // Handle Retry
            if (formAction == "Retry")
            {
                //// TODO: Retry should start a new asynchron transaction
                //// TODO: Proper implementation
                //this.msspTransId = "ID9876";

                //// Display the login process with option to "Cancel"
                //claims = null;
                //return new AdapterPresentation(1, this.msspTransId, "");
                throw new NotImplementedException("formAction 'Retry'");
            }

            logger.TraceEvent(TraceEventType.Error, 0, "Unsupported formAction: " + formAction);
            return new AdapterPresentation(AuthView.AuthError, new ServiceStatus(ServiceStatusCode.GeneralClientError), null); // TODO: consider client-side timeout
        }

    }

}
