package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getMatches;
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
import burp.j2ee.annotation.RunOnlyOnce;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;


/**
 * 
 * JBoss WS JUDDI console detection
 * 
 * 
 * 
 * 
 * 
 */
public class JBossJuddi implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private static final List<String> JBOSS_WS = Arrays.asList(
            "/juddi/"
    );

    private static final String TITLE = "JBoss WS JUDDI";
    private static final String DESCRIPTION = "J2EEscan identified the JBoss Juddi console.<br />"
            + "The jUDDI (Java Universal Description, Discovery and Integration) Registry "
            + "is a core component of the JBoss Enterprise SOA Platform. "
            + "It is the product's default service registry and comes included as "
            + "part of the product. In it are stored the addresses (end-point references) "
            + "of all the services connected to the Enterprise Service Bus. "
            + "It was implemented in JAXR and conforms to the UDDI specifications. <br /><br />";

    private static final String REMEDY = "Restrict access to the service if not needed";

    private static final byte[] GREP_STRING = ">JBoss JUDDI</title>".getBytes();

    private PrintWriter stderr;

    @RunOnlyOnce
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();

        String system = host.concat(Integer.toString(port));

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            for (String JBOSS_WS_PATH : JBOSS_WS) {

                try {
                    // Test the presence of JBossWS console
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), JBOSS_WS_PATH);
                    byte[] jbosswstest = helpers.buildHttpRequest(urlToTest);

                    byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, jbosswstest);

                    IResponseInfo jbosswsInfo = helpers.analyzeResponse(responseBytes);

                    if (jbosswsInfo.getStatusCode() == 200) {

                        // look for matches of our active check grep string
                        List<int[]> matches = getMatches(responseBytes, GREP_STRING, helpers);
                        if (matches.size() > 0) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    urlToTest,
                                    new CustomHttpRequestResponse(jbosswstest, responseBytes, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Low,
                                    Confidence.Certain
                            ));
                            return issues;
                        }
                    }
                } catch (MalformedURLException ex) {
                    stderr.println("Error creating URL " + ex.getMessage());
                }

            }

        }
        
        return issues;
    }
}
