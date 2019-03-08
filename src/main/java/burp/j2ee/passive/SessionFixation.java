package burp.j2ee.passive;

import static burp.HTTPMatcher.isJavaApplicationByURL;
import burp.HTTPParser;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import java.net.URL;


/**
 *
 * Basic dummy strategy to identify Session Fixation issues
 *
 * 
 * TODO 
 *  - improve the detection method, it's prone to FP.
 *  - More tests needed
 *  - Extends also to other common cookies, not only JSESSIONID
 * 
 */
public class SessionFixation implements PassiveRule {

    private static final String TITLE = "J2EE Session Fixation";
    private static final String DESCRIPTION = "J2EEscan identified a Session Fixation issue. <br />"
            + "Authenticating a user, or otherwise establishing a new user session, without invalidating any "
            + "existing session identifier gives an attacker the opportunity to steal authenticated sessions."  
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://www.owasp.org/index.php/Testing_for_Session_Fixation_(OTG-SESS-003)<br />"
            + "https://community.liferay.com/forums/-/message_boards/message/79181621<br />"
            + "https://cwe.mitre.org/data/definitions/384.html<br />"
            + "https://docs.spring.io/spring-security/site/docs/3.2.1.RELEASE/apidocs/org/springframework/security/web/authentication/session/SessionFixationProtectionStrategy.html"; 
            
    private static final String REMEDY = "Invalidate any existing session identifiers prior to authorizing a new user session.";
    
    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
            String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
            String httpServerHeader, String contentTypeResponse, String xPoweredByHeader) {

        URL curURL = reqInfo.getUrl();
        
        // Skip test for not j2ee applications
        if (!isJavaApplicationByURL(curURL)){
            return;
        }

        if (reqBody != null && 
                (reqBody.contains("password") || reqBody.contains("pwd") || reqBody.contains("passw")) &&
                (reqBody.contains("user") || reqBody.contains("mail")) 
                ) {

            String setCookieHeader = HTTPParser.getResponseHeaderValue(respInfo, "Set-Cookie");

          
            if (setCookieHeader == null && !setCookieHeader.contains("JSESSIONID")) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        TITLE,
                        DESCRIPTION,
                        REMEDY,
                        Risk.Medium,
                        Confidence.Tentative
                ));
            }
        }

    }

}

