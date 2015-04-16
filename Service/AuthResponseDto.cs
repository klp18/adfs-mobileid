
using System.Collections.Generic;
using System.Text;

namespace MobileId
{
    /// <summary>
    /// Output of RequestSignature(...) service call
    /// </summary>
    public class AuthResponseDto
    {
        public ServiceStatus Status { get; set; }

        /// <summary>
        /// optional details. Content depends on Status
        /// </summary>
        public object Detail { get; set;  }

        /// <summary>
        /// MSSP_TransID
        /// </summary>
        public string MsspTransId { get; set; }

        public byte[] Signature { get; set; }

        private Dictionary<AuthResponseExtension, object> _extensions = new Dictionary<AuthResponseExtension, object> { };

        /// <summary>
        /// Additional features (e.g. SubscriberInfo, UserAssistencePortalUrl)
        /// are accessible via a Dictionary. Extensions is garanteed to be a non-null Dictionary.
        /// If the server response contains a feature,
        /// the value of the feature can be retrieved with AuthResponseDto.Extensions[featureName],
        /// otherwise the key featureName is absent in the Dictionary.
        /// </summary>
        public Dictionary<AuthResponseExtension, object> Extensions
        {
            get { return _extensions;}
            set { if (value != null) _extensions = value;}
        }

        /// <summary>
        /// Mainly used to construct error response.
        /// </summary>
        /// <param name="StatusCode"></param>
        /// <param name="payload"></param>
        public AuthResponseDto(ServiceStatusCode statusCode, string payload)
        {
            this.Status = new ServiceStatus(statusCode);
            this.Detail = payload;
        }

        public AuthResponseDto(ServiceStatusCode statusCode)
        {
            this.Status = new ServiceStatus(statusCode);
        }

        public override string ToString() {
            StringBuilder sb = new StringBuilder();
            sb.Append("MsspTransid=").Append(MsspTransId);
            sb.Append(", Status: {").Append(Status);
            sb.Append("}, Detail: ").Append(Detail);
            return sb.ToString();
        }

    }

    public enum AuthResponseExtension
    {
        UserAssistencePortalUrl = 1,
        SubscriberInfo = 2
    }
}
