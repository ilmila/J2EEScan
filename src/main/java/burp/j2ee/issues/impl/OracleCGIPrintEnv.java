package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.URIMutator;
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
import java.util.List;


public class OracleCGIPrintEnv implements IModule {

    private static final String TITLE_INFO_DISCLOSURE = "Information Disclosure - cgi printenv";
    private static final String DESCRIPTION_INFO_DISCLOSURE = "J2EEscan identified an information disclosure issue "
            + "in the <i>/cgi-bin/printenv</i> path which reveals internal system information.";

    private static final List<String> CGIENV_PATHS = Arrays.asList(
            "/cgi-bin/printenv"
    );

    private PrintWriter stderr;
    private PrintWriter stdout;

    private static final byte[] GREP_STRINGS = "DOCUMENT_ROOT".getBytes();

    @RunOnlyOnce
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();

        String protocol = url.getProtocol();
        Boolean isSSL = (protocol.equals("https"));

        List<String> CGIENV_PATHS_MUTATED = URIMutator(CGIENV_PATHS);
        for (String CGIENV_PATH : CGIENV_PATHS_MUTATED) {

            try {

                // Test for printenv cgi 
                URL cgiUrlToTest = new URL(protocol, url.getHost(), url.getPort(), CGIENV_PATH);
                byte[] cgienvTest = helpers.buildHttpRequest(cgiUrlToTest);
                byte[] cgienvResponse = callbacks.makeHttpRequest(url.getHost(),
                        url.getPort(), isSSL, cgienvTest);
                IResponseInfo cgienvInfo = helpers.analyzeResponse(cgienvResponse);

                if (cgienvInfo.getStatusCode() == 200) {

                    String cgiResponse = helpers.bytesToString(cgienvResponse);
                    String cgienvResponseBody = cgiResponse.substring(cgienvInfo.getBodyOffset());

                    // look for matches of our active check grep string
                    List<int[]> matchHappyAxis = getMatches(helpers.stringToBytes(cgienvResponseBody),
                            GREP_STRINGS, helpers);

                    if ((matchHappyAxis.size() > 0)) {
                        stdout.println("cgi-bin/printenv detected " + cgiUrlToTest.toString());

                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                cgiUrlToTest,
                                new CustomHttpRequestResponse(cgienvTest, cgienvResponse, baseRequestResponse.getHttpService()),
                                TITLE_INFO_DISCLOSURE,
                                DESCRIPTION_INFO_DISCLOSURE,
                                "Disable remote access to the debug/test cgi",
                                Risk.Low,
                                Confidence.Certain
                        ));
                    }
                }
            } catch (MalformedURLException ex) {
                stderr.println("Malformed URL Exception " + ex);
            }
        }

        return issues;

    }

}
