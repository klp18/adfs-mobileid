using System;
using System.IO;
using System.Text;
using System.Xml;

namespace MobileId.Adfs
{
    class AdfsConfig
    {
        ulong _webClientMaxRequest = 100;
        string _adAttrMobile = "mobile";
        string _adAttrMidSerialNumber = "msNPCallingStationID".ToLower();
        string _defaultLoginPrompt = "Login with Mobile ID ({0})?";

        /// <summary>
        /// A WebClient can be re-used to send requests. If the number of requests exceed this number, 
        /// the WebClient must be re-cycled (i.e. closed and re-created). Default is 100.
        /// </summary>
        public ulong WebClientMaxRequest { 
            get { return _webClientMaxRequest; } 
            set { if (value > 0) _webClientMaxRequest = value; }
        }

        /// <summary>
        /// Name of AD attribute which contains the Mobile Number of the user.
        /// The name is case-insensitive and converted to lower case internally.
        /// If the AD attribute has multiple values, the last returned value will be used.
        /// Default is "mobile".
        /// </summary>
        public string AdAttrMobile { 
            get { return _adAttrMobile; }
            set { if (!String.IsNullOrEmpty(value) && !value.Contains(" "))
                _adAttrMobile = value.ToLower(System.Globalization.CultureInfo.InvariantCulture); 
            }
        }

        /// <summary>
        /// Name of AD attribute which contains the Serial Number (e.g. "MID0123456789ABC") of the 
        /// Mobile ID Token. The Serial Number is part of the Subject of the Mobile ID Certificate.
        /// The AD attribute name is case-insensitive and converted to lower case internally.
        /// If the AD attribute has multiple values, the last returned value will be used.
        /// Default is "msNPCallingStationID".
        /// </summary>
        public string AdAttrMidSerialNumber {
            get { return _adAttrMidSerialNumber;}
            set { if (!String.IsNullOrEmpty(value) && !value.Contains(" ")) 
                _adAttrMidSerialNumber = value.ToLower(System.Globalization.CultureInfo.InvariantCulture); 
            }
        }

        /// <summary>
        /// Default text to be sent via Mobile ID Service to user's mobile phone.
        /// The text may contain the place holder {0}, which will be expanded to 5-char random string.
        /// The text must not exceed the maximum length acceptable by Mobile ID Service (239 chars if encodable in gsm338 charset, 119 otherwise).
        /// </summary>
        public string DefaultLoginPrompt {
            get { return _defaultLoginPrompt; }
            set { if (!String.IsNullOrEmpty(value)) {
                int maxLength = MobileId.Util.maxDtbsLength(value);
                if (value.Length <= (value.Contains("{0}") ? maxLength-2 : maxLength)) {
                    // {0} will be expaned to a 5-char string
                    _defaultLoginPrompt = value;
                };
            }}
        }

        public static AdfsConfig CreateConfig(TextReader cfgStream)
        {
            if (cfgStream == null)
            {
                throw new ArgumentNullException("input stream is null");
            }

            AdfsConfig cfg = new AdfsConfig();
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
                    if (xml.Name == "mobileIdAdfs")
                    {
                        cfg.AdAttrMobile = xml["AdAttrMobile"];
                        if (!String.IsNullOrEmpty(s = xml["WebClientMaxRequest"]))
                          cfg.WebClientMaxRequest = ulong.Parse(s);
                        cfg.AdAttrMidSerialNumber = xml["AdAttrMidSerialNumber"];
                        cfg.DefaultLoginPrompt = xml["DefaultLoginPrompt"];
                        // TODO: update on change
                        break;
                    }
                }
                xml.Close();
            }
            return cfg;
        }

        public static AdfsConfig CreateConfig(string cfgContent)
        {
            if (String.IsNullOrEmpty(cfgContent))
                throw new ArgumentNullException("cfgContent is null or empty");
            using (TextReader stream = new StringReader(cfgContent))
            {
                return CreateConfig(stream);
            }

        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder(196); // TODO: update on change
            // sorted alphabetically in name
            sb.Append("{AdAttrMobile: \"").Append(_adAttrMobile);
            sb.Append("\"; AdAttrMidSerialNumber: \"").Append(_adAttrMidSerialNumber);
            sb.Append("\"; DefaultLoginPrompt: \"").Append(_defaultLoginPrompt);
            sb.Append("\"; WebClientMaxRequest: ").Append(_webClientMaxRequest);
            // TODO: update on change
            sb.Append("}");
            return sb.ToString();
        }
    }
}
