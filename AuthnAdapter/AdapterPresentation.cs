﻿using System;
using Microsoft.IdentityServer.Web.Authentication.External;

namespace MobileId.Adfs
{
    class AdapterPresentation : IAdapterPresentation, IAdapterPresentationForm
    {
        private AuthView viewId;        // determines which message should be should
        private string param;           // additional parameter;
        private ServiceStatus rspStatus;

        public AdapterPresentation(AuthView currentState)
        {
            viewId = currentState;
            param = null;
        }
        public AdapterPresentation(AuthView currentState, string additionalParam)
        {
            viewId = currentState;
            param = additionalParam;
        }
        public AdapterPresentation(AuthView currentState, ServiceStatus svcStatus, string svcDetail)
        {
            viewId = currentState;
            rspStatus = svcStatus;
            param = svcDetail;
        }

        // Returns the title string for the web page which presents the HTML form content to the end user
        public string GetPageTitle(int lcid)
        {
            return "Login with Mobile ID";
        }

        private const string loginFormCommonHtml = @"<form method=""post"" id=""midLoginForm""><input id=""context"" type=""hidden"" name=""Context"" value=""%Context%""/>";
        // The next string is documented as a required field in MSDN, but provokes "duplicated authMethod field" server error response in ADFS 3.5.
        // <input id=""authMethod"" type=""hidden"" name=""AuthMethod"" value=""%AuthMethod%""/>"  
            
        // Returns the HTML Form fragment that contains the adapter user interface. This data will be included in the web page that is presented
        // to the cient.
        public string GetFormHtml(int lcid)
        {
            switch (this.viewId)
            {
                case AuthView.SignRequestSent:
                    return "<p>A Mobile ID message has been sent to " + this.param
                        + ". Please follow the instructions on the mobile phone.</p>" + loginFormCommonHtml
+ @"<div class=""submitMargin"" id=""mid_Continue""><input id=""midContinueButton"" type=""submit"" name=""Action"" value=""Continue""/></div></form>
<script>
document.getElementById('mid_Continue').style.visibility='hidden';
window.setTimeout(function continueMobileIdAuth() {document.getElementById('midContinueButton').click();},15000);
</script>
<div id=""midSpin""></div>
<script src=""/adfs/portal/script/spin.js""></script>
<script>new Spinner({lines:13, length:22, width:11, radius:25, corners:1, rotate:0,
  direction:1, color:'#000', speed:1, trail:57, shadow:false, hwaccel:false, 
  className:'spinner', zIndex:2e9, top:'70%', left:'45%'})
.spin(document.getElementById('midSpin'));
</script>";
                case AuthView.AuthError:
                    if (this.rspStatus != null)
                        return loginFormCommonHtml + "</form><p>" + this.rspStatus.Code + " (" + this.rspStatus.Message + ")</p>" + this.param;
                    else
                        return loginFormCommonHtml + "</form><p>" + this.param ;
                case AuthView.UserClickContinued:
                    throw new NotImplementedException("AuthView " + this.viewId);   // TODO
                default:
                    throw new NotSupportedException("AuthView " + this.viewId); // TODO
            };
        }

        // Return any external resources, ie references to libraries etc., that should be included in 
        // the HEAD section of the presentation form html. 
        public string GetFormPreRenderHtml(int lcid)
        {
            return "";
        }
    }

    /// <summary>
    ///  viewId relevant for presentation
    /// </summary>
    public enum AuthView
    {
        SignRequestSent = 1,
        UserClickContinued = 2,
        AuthError = 9
    }

}
