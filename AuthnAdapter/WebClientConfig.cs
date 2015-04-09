using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace MobileId
{
    //    public class WebClientConfig : ConfigurationSection (does not work)

    /// <summary>
    /// Encapsulation of all configuration parameters needed by WebClientImpl
    /// </summary>
    public class WebClientConfig
    {
        // mandatory input from caller
        string _apId = null;
        string _sslCertThumbprint = null;

        // optional input from caller
        string _sslCaCertDN = "CN=Swisscom Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch";
        StoreLocation _sslKeyStore = StoreLocation.CurrentUser;
        UserLanguage _userLanguageDefault = UserLanguage.en;
        string _serviceUrlPrefix = "https://mobileid.swisscom.com/soap/services/";
        // string _dtbsPrefix = null;
        bool _srvSideValidation = true;
        int _requestTimeOutSeconds = 80;
        string _seedApTransId = "Some ASCII text to be used to build the unique AP_TransId in request";
        bool _enableSubscriberInfo = false;
        bool _ignoreUserSn = false;
        bool _ignoreUserSnChange = false;
        int _pollResponseDelaySeconds = 15;
        int _pollResponseIntervalSeconds = 1;

        //// not used. doesn't work
        ///// <summary>
        ///// Build a configuration from NameValueCollection, such that from a section in app.config file.
        ///// </summary>
        ///// <param name="appCfg"></param>
        //public WebClientConfig(NameValueCollection appCfg)
        //{
        //    Trace.Assert(appCfg != null, "appCfg is null");
        //    // if (appCfg == null) throw new ArgumentNullException("appCfg is null");
        //    this.ApId = appCfg["ApId"];
        //}

        public static WebClientConfig CreateConfigFromFile(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
            {
                throw new ArgumentNullException("config fileName is null or empty");
                // TODO: construct a default filename
            }
            using (FileStream fs = File.OpenRead(fileName))
            using (TextReader tr = new StreamReader(fs))
            {
                return CreateConfig(tr);
            };
        }

        public static WebClientConfig CreateConfig(string cfgContent)
        {
            if (String.IsNullOrEmpty(cfgContent))
                throw new ArgumentNullException("cfgContent is null or empty");
            using (TextReader stream = new StringReader(cfgContent)) {
                return CreateConfig(stream);
            }

        }

        public static WebClientConfig CreateConfig(TextReader cfgStream)
        {
            if (cfgStream == null)
            {
                throw new ArgumentNullException("input stream is null");
            }
            WebClientConfig cfg = new WebClientConfig();

            XmlReaderSettings xmlSetting = new XmlReaderSettings();
            xmlSetting.CloseInput = true;
            xmlSetting.IgnoreProcessingInstructions = true;
            xmlSetting.IgnoreWhitespace = true;
            using (XmlReader xml = XmlReader.Create(cfgStream, xmlSetting))
            {
                String s;
                while (xml.Read())
                {
                    // we process only the <mobileIdClient .../> element
                    if (xml.Name == "mobileIdClient")
                    {
                        // Warning: Due to input validation, the processing order of the attributes may be important.
                        cfg.ApId = xml["AP_ID"];
                        // cfgMid.DtbsPrefix = xml["DtbsPrefix"];
                        if (!string.IsNullOrWhiteSpace(s = xml["RequestTimeOutSeconds"]))
                            cfg.RequestTimeOutSeconds = int.Parse(s);
                        cfg.ServiceUrlPrefix = xml["ServiceUrlPrefix"];
                        if (!string.IsNullOrEmpty(s = xml["SrvSideValidation"]))
                            cfg.SrvSideValidation = bool.Parse(s);
                        cfg.SslCertThumbprint = xml["SslCertThumbprint"];
                        if (!string.IsNullOrEmpty(s = xml["SslKeystore"]))
                            cfg.SslKeystore = Util.ParseKeyStoreLocation(s);
                        if (!string.IsNullOrEmpty(s = xml["SslRootCaCertDN"]))
                            cfg.SslRootCaCertDN = s;
                        if (!string.IsNullOrEmpty(s = xml["EnableSubscriberInfo"]))
                            cfg.EnableSubscriberInfo = Boolean.Parse(s);
                        cfg.SeedApTransId = xml["SeedApTransId"];
                        if (!string.IsNullOrWhiteSpace(s = xml["PollResponseDelaySeconds"]))
                            cfg.PollResponseDelaySeconds = int.Parse(s);
                        if (!string.IsNullOrWhiteSpace(s = xml["PollResponseIntervalSeconds"]))
                            cfg.PollResponseIntervalSeconds = int.Parse(s);
                        // TODO: add a rule if a new config parameter has been introduced
                        
                        break;
                    }
                }
                xml.Close();
            }

            return cfg;
        }

        // TODO: input validation of config parameters

        /// <summary>
        /// AP_ID of the client, s. Reference Guide of Mobile ID
        /// </summary>
        [ConfigurationProperty("ApId", IsRequired = true)]
        public string ApId { 
            get {
                return _apId;
            } 
            set {
                if (string.IsNullOrEmpty(value))
                    throw new ArgumentNullException("ApId is null or empty");
                if (! Util.IsXmlSafe(value))
                    throw new ArgumentException("ApId contains bad chars");
                _apId = value;
            }
        }

        public UserLanguage UserLanguageDefault 
        { 
            get { return _userLanguageDefault; }
            set { _userLanguageDefault = value; } 
        }

        [ConfigurationProperty("SslKeystore", IsRequired = false, DefaultValue = "CurrentUser")]
        public StoreLocation SslKeystore
        { 
            get {return _sslKeyStore;}
            set {
                switch (value.ToString())
                {
                    case "CurrentUser" : _sslKeyStore = StoreLocation.CurrentUser; break;
                    case "LocalMachine" : _sslKeyStore = StoreLocation.LocalMachine; break;
                    default: throw new ArgumentOutOfRangeException("SslKeystore is neither 'CurrentUser' nor 'LocalMachine'");
                }
            }
        }

        [ConfigurationProperty("SslCertThumbprint", IsRequired = true, DefaultValue = "CurrentUser")]
        public string SslCertThumbprint {
            get { return _sslCertThumbprint; }
            set { _sslCertThumbprint = value; }
        }

        /// <summary>
        /// Distinguished Name of Root CA Certificate in the CA Chain of the SSL Server Certificate for Mobile ID Service
        /// </summary>
        [ConfigurationProperty("SslRootCaCertDN", IsRequired = true)]
        public string SslRootCaCertDN {
            get { return _sslCaCertDN; }
            set { if (! string.IsNullOrEmpty(value)) _sslCaCertDN = value;  }
        }

        public string ServiceUrlPrefix {
            get { return _serviceUrlPrefix; }
            set { if (! string.IsNullOrEmpty(value)) _serviceUrlPrefix = value;}
        }

        //public string DtbsPrefix { 
        //    get { return _dtbsPrefix; }
        //    set { _dtbsPrefix = value; }
        //}

        public bool SrvSideValidation { 
            get { return _srvSideValidation; }
            set { _srvSideValidation = value; }
        }

        public string SeedApTransId {
            get { return _seedApTransId; }
            set { if (value != null) _seedApTransId = value; }
        }

        public bool EnableSubscriberInfo { 
            get { return _enableSubscriberInfo;}
            set { _enableSubscriberInfo = value; }
        }

        public bool IgnoreUserSn {
            get { return _ignoreUserSn; }
            set { _ignoreUserSn = value; }
        }

        public bool IgnoreUserSnChange
        {
            get { return _ignoreUserSnChange; }
            set { _ignoreUserSnChange = value; }
        }

        public int RequestTimeOutSeconds
        {
            get { return _requestTimeOutSeconds; }
            set { if (value > 0 && value < 300) _requestTimeOutSeconds = value; }
        }

        /// <summary>
        /// Timespan, in seconds, between the asynchronous RequestSignature(...) and the first PollSignature(...)
        /// Must be an integer between 1 and RequestTimeOutSeconds.
        /// </summary>
        public int PollResponseDelaySeconds
        {
            get { return _pollResponseDelaySeconds; }
            set { if (value > 0 && value < _requestTimeOutSeconds) _pollResponseDelaySeconds = value; }
        }

        /// <summary>
        /// Timespan, in seconds, between two consecutive PollSignature(...).
        /// Must be an integer between 1 and RequestTimeOutSeconds.
        /// </summary>
        public int PollResponseIntervalSeconds
        {
            get { return _pollResponseIntervalSeconds; }
            set { if (value > 0 && value < _requestTimeOutSeconds) _pollResponseIntervalSeconds = value; }
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder(512);  // TODO: update on change
            // sorted alphabetically in name
            sb.Append("{ApId: \"").Append(_apId);
            // sb.Append(", DtbsPrefix=").Append(_dtbsPrefix);
            sb.Append("\"; EnableSubscriberInfo:").Append(_enableSubscriberInfo);
            sb.Append("; IgnoreUserSn:").Append(_ignoreUserSn);
            sb.Append("; IgnoreUserSnChange:").Append(_ignoreUserSnChange);
            sb.Append("; PollResponseDelaySeconds:").Append(_pollResponseDelaySeconds);
            sb.Append("; PollResponseIntervalSeconds:").Append(_pollResponseIntervalSeconds);
            sb.Append("; RequestTimeOutSeconds:").Append(_requestTimeOutSeconds);
            sb.Append("; SeedApTransId:\"").Append(_seedApTransId);
            sb.Append("\"; ServiceUrlPrefix=\"").Append(_serviceUrlPrefix);
            sb.Append("\"; SrvSideValidation:").Append(_srvSideValidation);
            sb.Append("; SslKeystore:").Append(_sslKeyStore);
            sb.Append("; SslCertThumbprint:\"").Append(_sslCertThumbprint);
            sb.Append("\"; SslRootCaCertDN:\"").Append(_sslCaCertDN);
            sb.Append("\"; UserLanguageDefault:\"").Append(_userLanguageDefault);
            sb.Append("\"}");
            return sb.ToString();


        }
    }
}
