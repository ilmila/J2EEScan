package burp.j2ee.issues.impl;

import static burp.HTTPParser.getResponseHeaderValue;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 *
 * UTF8 Response Splitting
 * 
 * 
 */
public class UTF8ResponseSplitting implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private static final String TITLE = "UTF8 Response Splitting";
    private static final String DESCRIPTION = "J2EEscan identified a Response Splitting vulnerability.<br /><br />"
            + "The application seems to ignore CRLF newline character (0x0a), but accepts utf8 newline chars<br /><br />"
            + "<b>References</b><br />"
            + "http://www.fhhyc.com/is-it-possible-to-exploit-this-line-feed/<br />"
            + "https://www.owasp.org/index.php/HTTP_Response_Splitting<br />"
            + "https://www.owasp.org/index.php/Testing_for_HTTP_Splitting/Smuggling_(OTG-INPVAL-016)";

    private static final String REMEDY = "Usually this threat is introduced by underline libraries and technologies.";

    private static final byte[] INJ = "%E5%98%8A%E5%98%8DX-Injection:%20test".getBytes();

    private PrintWriter stderr;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();

        String system = host.concat(Integer.toString(port));

        String protocol = url.getProtocol();
        Boolean isSSL = (protocol.equals("https"));

        stderr.println(insertionPoint.getInsertionPointName());
                    
        // make a request containing our injection test in the insertion point
        byte[] checkRequest = insertionPoint.buildRequest(INJ);

        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest);

        IResponseInfo responseInfo = helpers.analyzeResponse(checkRequestResponse.getResponse());
   
        if (getResponseHeaderValue(responseInfo, "X-Injection") != null) {
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    checkRequestResponse,
                    TITLE,
                    DESCRIPTION,
                    REMEDY,
                    Risk.Medium,
                    Confidence.Certain
            ));
        }

        return issues;

    }
}
