package burp.j2ee;

import burp.HTTPParser;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.j2ee.passive.ApacheStrutsS2023Rule;
import burp.j2ee.passive.ApacheTomcatRule;
import burp.j2ee.passive.ExceptionRule;
import burp.j2ee.passive.HttpServerHeaderRule;
import burp.j2ee.passive.JSPostMessage;
import burp.j2ee.passive.JettyRule;
import burp.j2ee.passive.PassiveRule;
import burp.j2ee.passive.SessionFixation;
import burp.j2ee.passive.SessionIDInURL;
import burp.j2ee.passive.SqlQueryRule;


public class PassiveScanner {

    /**
     * List of passive rules
     */
    static PassiveRule[] PASSIVE_RULES = {new ApacheTomcatRule(), 
        new ExceptionRule(), 
        new HttpServerHeaderRule(), 
        new SqlQueryRule(),
        new ApacheStrutsS2023Rule(),
        new JettyRule(),
        new SessionIDInURL(),
        new JSPostMessage(),
        new SessionFixation()
    };

    public static void scanVulnerabilities(IHttpRequestResponse baseRequestResponse,
                                           IBurpExtenderCallbacks callbacks) {

        IExtensionHelpers helpers = callbacks.getHelpers();

        byte[] rawRequest = baseRequestResponse.getRequest();
        byte[] rawResponse = baseRequestResponse.getResponse();

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        IResponseInfo respInfo = helpers.analyzeResponse(rawResponse);

        //Body (without the headers)
        String reqBody = getBodySection(rawRequest, reqInfo.getBodyOffset());
        String respBody = getBodySection(rawResponse, respInfo.getBodyOffset());

        String httpServerHeader = HTTPParser.getResponseHeaderValue(respInfo, "Server");
        String contentTypeResponse = HTTPParser.getResponseHeaderValue(respInfo, "Content-Type");
        String xPoweredByHeader = HTTPParser.getResponseHeaderValue(respInfo, "X-Powered-By");

        for(PassiveRule scanner : PASSIVE_RULES) {
            scanner.scan(callbacks,baseRequestResponse,reqBody,respBody,reqInfo,respInfo,
                    httpServerHeader,contentTypeResponse, xPoweredByHeader);
        }

    }


    private static String getBodySection(byte[] respBytes, int bodyOffset) {
        return new String(respBytes, bodyOffset, respBytes.length - bodyOffset);
    }
}
