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
 * Test for JBoss jBPM Admin Console
 * 
 * https://docs.jboss.org/jbpm/v5.1/userguide/ch11.html
 * 
 */
public class JBossjBPMAdminConsole implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;

    private static final String TITLE = "JBoss jBPM Admin Console";
    private static final String DESCRIPTION = "J2EEscan identified the jBPM Admin Console "
            + "installed on the remote system. The JBoss Business Process Manager (jBPM) "
            + "is a workflow management tool that provides the user with control "
            + "over business processes and languages. ";

    private static final String REMEDY = "Change default/weak password and/or restrict access to the management console only from trusted hosts/networks";

    private static final List<String> JBOSS_jBPM_PATHS = Arrays.asList(
            "/jbpm-console/app/tasks.jsf"
    );

    private static final List<byte[]> GREP_STRINGS = Arrays.asList(
            "<title>JBoss jBPM Administration Console</title>".getBytes()
    );

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

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            List<String> JBOSS_jBPM_PATHS_MUTATED = URIMutator(JBOSS_jBPM_PATHS);
            for (String JBOSS_jBPM_PATH : JBOSS_jBPM_PATHS) {

                try {

                    URL urlToTest;
                    urlToTest = new URL(protocol, url.getHost(), url.getPort(), JBOSS_jBPM_PATH);

                    byte[] jbosstest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, jbosstest);

                    IResponseInfo jbossAdminInfo = helpers.analyzeResponse(response);

                    if (jbossAdminInfo.getStatusCode() == 200) {

                        // look for matches of our active check grep string
                        for (byte[] GREP_STRING : GREP_STRINGS) {

                            List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                            if (matches.size() > 0) {
                                callbacks.addScanIssue(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        new URL(protocol, url.getHost(), url.getPort(), JBOSS_jBPM_PATH),
                                        new CustomHttpRequestResponse(jbosstest, response, baseRequestResponse.getHttpService()),
                                        TITLE,
                                        DESCRIPTION,
                                        REMEDY,
                                        Risk.Medium,
                                        Confidence.Certain
                                ));
                            }
                        }
                    }
                } catch (MalformedURLException ex) {
                    stderr.println("MalformedURLException " + ex.toString());
                }

            }
        }
        
        return issues;

    }
}
