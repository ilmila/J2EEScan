package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.WeakPassword;
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
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Verify if the JBoss Admin Console is reachable
 *
 * http://docs.jboss.org/jbossas/6/Admin_Console_Guide/en-US/html/Administration_Console_User_Guide-Accessing_the_Console.html
 * http://docs.jboss.org/jbossas/6/Admin_Console_Guide/en-US/html/
 *
 */
public class JBossAdminConsole implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private static final String TITLE = "JBoss Admin Console";
    private static final String DESCRIPTION = "J2EEscan identified the JBoss Application Server administration console "
            + "installed on the remote system";

    private static final String TITLE_WEAK_PASSWORD = "JBoss Admin Console Weak Password";
    private static final String DESCRIPTION_WEAK_PASSWORD = "J2EEscan identified the JBoss Application Server administration console is "
            + "installed on the remote system with a weak password. This issue allows a remote attacker to install "
            + "remote web backdoors on the AS<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://docs.jboss.org/jbossas/6/Admin_Console_Guide/en-US/html/Administration_Console_User_Guide-Accessing_the_Console.html<br />"
            + "http://docs.jboss.org/jbossas/6/Admin_Console_Guide/en-US/html/";

    private static final String REMEDY = "Change default/weak password and/or restrict access to the management console only from trusted hosts/networks";

    private static final List<String> JBOSS_ADMIN_PATHS = Arrays.asList(
            "/admin-console/login.seam;jsessionid=4416F53DDE1DBC8081CDBDCDD1666FB0"
    );
    // <title>JBoss AS Administration Console</title>
    // <title>JBoss AS Admin Console</title>
    private static final byte[] GREP_STRING = "<title>JBoss AS Admin".getBytes();
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

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            for (String JBOSS_ADMIN_PATH : JBOSS_ADMIN_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), JBOSS_ADMIN_PATH);
                    byte[] jbosstest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, jbosstest);

                    IResponseInfo jbossAdminInfo = helpers.analyzeResponse(response);

                    if (jbossAdminInfo.getStatusCode() == 200) {

                        // look for matches of our active check grep string
                        List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                        if (matches.size() > 0) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    new URL(protocol, url.getHost(), url.getPort(), JBOSS_ADMIN_PATH),
                                    new CustomHttpRequestResponse(jbosstest, response, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Low,
                                    Confidence.Certain
                            ));

                            /**
                             * Try to bruteforce the login from
                             *
                             * Successful login attempt
                             *
                             * login_form=login_form&login_form%3Aname=test&login_form%3Apassword=tes&login_form%3Asubmit=Login&javax.faces.ViewState=
                             *
                             * HTTP/1.1 302 Moved Temporarily Server:
                             * Apache-Coyote/1.1 X-Powered-By: Servlet 2.5;
                             * JBoss-5.0/JBossWeb-2.1 X-Powered-By: JSF/1.2
                             * Location:
                             * http://wwww.example.com/admin-console/secure/summary.seam?conversationId=391
                             * Set-Cookie:
                             * JSESSIONID=9D6DCB5F2E0CA1AAE374FE763EED9C79;
                             * Path=/admin-console
                             */
                            // Retrieve the javax
                            // id="javax.faces.ViewState" value="
                            Pattern p = Pattern.compile("id=\"javax.faces.ViewState\" value=\"(.*?)\"");
                            Matcher matcher = p.matcher(helpers.bytesToString(response));

                            if (matcher.find()) {
                                String viewState = matcher.group(1);
                                byte[] jbosstestPOST = callbacks.getHelpers().toggleRequestMethod(jbosstest);

                                IRequestInfo jbosstestPOSTInfo = helpers.analyzeRequest(jbosstestPOST);

                                List<String> requestHeadersToTest = new ArrayList<>(jbosstestPOSTInfo.getHeaders());
                                requestHeadersToTest.add("Cookie: JSESSIONID=11C3E6C1B22DB1AC64344FFFE6FBF811");

                                //login_form=login_form&login_form%3Aname=test&login_form%3Apassword=tes&login_form%3Asubmit=Login&javax.faces.ViewState=
                                jbosstestPOST = helpers.addParameter(jbosstestPOST, helpers.buildParameter("login_form", "login_form", IParameter.PARAM_BODY));
                                jbosstestPOST = helpers.addParameter(jbosstestPOST, helpers.buildParameter("login_form%3Asubmit", "Login", IParameter.PARAM_BODY));
                                jbosstestPOST = helpers.addParameter(jbosstestPOST, helpers.buildParameter("javax.faces.ViewState", helpers.urlEncode(viewState), IParameter.PARAM_BODY));

                                List<Map.Entry<String, String>> credentials = WeakPassword.getCredentials();
                                for (Map.Entry<String, String> credential : credentials) {
                                    byte[] jbosstestPOSTBruteforce = jbosstestPOST;
                                    jbosstestPOSTBruteforce = helpers.addParameter(jbosstestPOSTBruteforce, helpers.buildParameter("login_form%3Aname", credential.getKey(), IParameter.PARAM_BODY));
                                    jbosstestPOSTBruteforce = helpers.addParameter(jbosstestPOSTBruteforce, helpers.buildParameter("login_form%3Apassword", credential.getValue(), IParameter.PARAM_BODY));

                                    byte[] evilMessage = callbacks.getHelpers().buildHttpMessage(requestHeadersToTest, Arrays.copyOfRange(jbosstestPOSTBruteforce, helpers.analyzeRequest(jbosstestPOSTBruteforce).getBodyOffset(), jbosstestPOSTBruteforce.length));
                                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), evilMessage);

                                    IResponseInfo statusAuthResponse = helpers.analyzeResponse(checkRequestResponse.getResponse());

                                    if (statusAuthResponse.getStatusCode() >= 300 && statusAuthResponse.getStatusCode() < 400) {

                                        List<String> responseHeaders = statusAuthResponse.getHeaders();

                                        for (int h = 0; h < responseHeaders.size(); h++) {
                                            if (responseHeaders.get(h).toLowerCase().startsWith("location".toLowerCase())
                                                    && responseHeaders.get(h).toLowerCase().contains("secure/summary.seam")) {

                                                issues.add(new CustomScanIssue(
                                                        baseRequestResponse.getHttpService(),
                                                        new URL(protocol, url.getHost(), url.getPort(), JBOSS_ADMIN_PATH),
                                                        new CustomHttpRequestResponse(evilMessage, checkRequestResponse.getResponse(), baseRequestResponse.getHttpService()),
                                                        TITLE_WEAK_PASSWORD,
                                                        DESCRIPTION_WEAK_PASSWORD,
                                                        REMEDY,
                                                        Risk.Low,
                                                        Confidence.Certain
                                                ));

                                                return issues;
                                            }
                                        }
                                    }
                                }

                            } else {
                                stderr.println("While testing JBoss Admin panel Weak password"
                                        + " it was not possible to retrieve Javax.faces.viewstate");
                            }

                        }
                    }

                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }
            }
        }

        return issues;
    }

}
