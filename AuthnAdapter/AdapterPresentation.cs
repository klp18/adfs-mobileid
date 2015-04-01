using System;
using Microsoft.IdentityServer.Web.Authentication.External;

namespace MobileId.Adfs
{
    class AdapterPresentation : IAdapterPresentation, IAdapterPresentationForm
    {
        private AuthView viewId;        // determines which message should be should
        private string param;           // additional parameter
        private int intParam;           // additional parameter
        private AdfsConfig adfsConfig;
        private ServiceStatus rspStatus;

        public AdapterPresentation(AuthView currentState, AdfsConfig adfsConfig)
        {
            viewId = currentState;
            this.adfsConfig = adfsConfig;
            param = null;
        }

        public AdapterPresentation(AuthView currentState, AdfsConfig adfsConfig, string param, int intParam)
        {
            viewId = currentState;
            this.adfsConfig = adfsConfig;
            this.param = param;
            this.intParam = intParam;
        }

        public AdapterPresentation(AuthView currentState, AdfsConfig adfsConfig, string param)
        {
            viewId = currentState;
            this.adfsConfig = adfsConfig;
            this.param = param;
        }

        public AdapterPresentation(AuthView currentState, AdfsConfig adfsConfig, ServiceStatus svcStatus, string svcDetail)
        {
            viewId = currentState;
            this.adfsConfig = adfsConfig;
            rspStatus = svcStatus;
            param = svcDetail;
        }

        // MS API: Returns the title string for the web page which presents the HTML form content to the end user
        public string GetPageTitle(int lcid)
        {
            return "Login with Mobile ID";
        }

        private const string loginFormCommonHtml = @"<form method=""post"" id=""midLoginForm""><input id=""context"" type=""hidden"" name=""Context"" value=""%Context%""/>";
        // The next string is documented as a required field in MSDN, but provokes "duplicated authMethod field" server error response in ADFS 3.5.
        // <input id=""authMethod"" type=""hidden"" name=""AuthMethod"" value=""%AuthMethod%""/>"  
            
        // MS API: Returns the HTML Form fragment that contains the adapter user interface. This data will be included in the web page that is presented
        // to the cient.
        public string GetFormHtml(int lcid)
        {
            string s,ret;
            switch (this.viewId)
            {
                case AuthView.SignRequestSent:
                    return "<p>A Mobile ID message has been sent to " + this.param
                        + ". Please follow the instructions on the mobile phone.</p>" + loginFormCommonHtml
+ @"<div class=""submitMargin"" id=""mid_Continue""><input id=""midContinueButton"" type=""submit"" name=""Action"" value=""Continue""/></div></form>
<script>
document.getElementById('mid_Continue').style.visibility='hidden';
window.setTimeout(function continueMobileIdAuth() {document.getElementById('midContinueButton').click();}," + intParam + @");
</script>
<div id=""midSpin""></div>
<script src=""/adfs/portal/script/spin.js""></script>
<script>new Spinner({lines:13, length:22, width:11, radius:25, corners:1, rotate:0,
  direction:1, color:'#000', speed:1, trail:57, shadow:false, hwaccel:false, 
  className:'spinner', zIndex:2e9, top:'70%', left:'45%'})
.spin(document.getElementById('midSpin'));
</script>";

                case AuthView.AuthError:
                    s = (this.rspStatus != null)
                        ? this.rspStatus.Code + " (" + this.rspStatus.Message + ")</p><p>" + this.param
                        : this.param;
                    return loginFormCommonHtml 
+ @"<input name=""" + (this.adfsConfig.SsoOnCancel ? "Single" : "Local") + @"SignOut"" type=""hidden"" checked=""checked"" value=""Sign Out""/>
<div class=""submitMargin""><p>" + s + @"</p></div>
<div class=""submitMargin""><input name=""SignOut"" class=""submit"" id=""midSignOutButton"" type=""submit"" value=""Cancel Login""/></div>
</form>";

                case AuthView.TransferCtx:
                    return loginFormCommonHtml +
                        @"<div class=""submitMargin"" id=""mid_Continue""><input id=""midContinueButton"" type=""submit"" name=""Action"" value=""Continue""/></div></form>
<script>
document.getElementById('mid_Continue').style.visibility='hidden';
document.getElementById('midContinueButton').click();
</script>";
                case AuthView.AutoLogout:
                    // return @"<form id=""idpForm"" action=""/adfs/ls/idpinitiatedsignon"" method=""post"">
                    return @"<form id=""midLogoutForm"" method=""post""><input id=""context"" type=""hidden"" name=""Context"" value=""%Context%""/>
<input name=""" + (this.adfsConfig.SsoOnCancel ? "Single" : "Local") + @"SignOut"" type=""hidden"" checked=""checked"" value=""Sign Out""/>
<input name=""SignOut"" class=""submit"" id=""midSignOutButton"" type=""submit"" value=""Sign Out""/>
</form>
<script>
document.getElementById('midSignOutButton').click();
</script>
";
                case AuthView.RetryOrCancel:
                    s = (this.rspStatus != null)
                        ? this.rspStatus.Code + " (" + this.rspStatus.Message + ")</p><p>" + this.param
                        : this.param;
                    ret = @"<script>
function onClickMidRetry() {document.getElementById('midHiddenSignOut').disabled=true;}
</script>
" + loginFormCommonHtml
+ @"<input name=""" + (this.adfsConfig.SsoOnCancel ? "Single" : "Local") + @"SignOut"" type=""hidden"" id=""midHiddenSignOut"" checked=""checked"" value=""Sign Out""/>
<div class=""submitMargin""><p>" + s + @"</p></div>
<div class=""submitMargin""><input name=""SignOut"" class=""submit"" id=""midSignOutButton"" type=""submit"" value=""Cancel Login""/>
&nbsp;<input name=""Action"" class=""submit"" id=""midActionButton"" onclick=""onClickMidRetry()"" type=""submit"" value=""Retry""/>
</div></form>";
                    if (this.adfsConfig.ExpShowWSignOut)
                        ret += @"<form action=""/adfs/ls/?ws=wsignout1.0"" method=""post""><div class=""submitMargin"">
<input name=""WSignOut"" class=""submit"" id=""midWSignOutButton"" type=""submit"" value=""WSignOut""/>
</div></form>
";
                    return ret;
                default:
                    throw new NotSupportedException("AuthView " + this.viewId);
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
        TransferCtx = 2,
        RetryOrCancel = 3,
        AutoLogout = 4,
        AuthError = 9
    }

}
