package burp.j2ee.passive;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * Improved detection for session identifiers in URL
 * 
 * The passive rule checks the usage of path parameters on common J2EE platforms
 * 
 * References:
 *  - CWE-598
 *  - http://www.jtmelton.com/2011/02/02/beware-the-http-path-parameter/
 *  - https://doriantaylor.com/policy/http-url-path-parameter-syntax
 * 
 */
public class SessionIDInURL implements PassiveRule {

    private static final List<String> SESSIONIDs = new ArrayList<>(Arrays.asList(";jsessionid"));


    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse, String xPoweredByHeader) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        
        URL curURL = reqInfo.getUrl();
        
        /**
         * session identifiers in URL (path parameter)
         * Improved detection for session identifiers
         */
        for (String identifier : SESSIONIDs) {
            
            if (curURL.toString().contains(identifier)) {
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Session Token in Query Fragment",
                        "J2EEScan identified session identifiers in the URLs; these information  may be logged in various locations,"
                                + "including the user's browser, the web server, and any forward or reverse proxy servers between the "
                                + "two endpoints. <br /><br />"
                                + "URLs may also be displayed on-screen, bookmarked or emailed around by users. "
                                + "They may be disclosed to third parties via the Referer header when any off-site links are followed. <br />"
                                + "Placing session tokens into the URL increases the risk that they will be captured by an attacker.",
                        "Sensitive information within URLs may be logged in various locations, including the user's browser, the web server, and any forward or"
                                + " reverse proxy servers between the two endpoints. URLs may also be displayed on-screen, bookmarked or emailed around by users. <br />"
                                + "They may be disclosed to third parties via the Referer header when any off-site links are followed. <br />"
                                + "Placing session tokens into the URL increases the risk that they will be captured by an attacker.",
                        Risk.Medium,
                        Confidence.Firm
                ));
            }
        }
           
    }
}
