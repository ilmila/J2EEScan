package burp.j2ee.passive;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.SoftwareVersions;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApacheTomcatRule implements PassiveRule {

    private static final Pattern TOMCAT_PATTERN = Pattern.compile("Apache Tomcat/([\\d\\.]+)", Pattern.DOTALL | Pattern.MULTILINE);
    private static final Pattern JVM_RULE = Pattern.compile("\"><small>(1\\.\\d\\.[\\w\\-\\_\\.]+)<", Pattern.DOTALL | Pattern.MULTILINE);

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse, String xPoweredByHeader) {
        IExtensionHelpers helpers = callbacks.getHelpers();

        /**
         * Detect Apache Tomcat
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {

            Matcher matcher = TOMCAT_PATTERN.matcher(respBody);

            if (matcher.find()) {
                String version = matcher.group(1);

                SoftwareVersions.getIssues("Apache Tomcat", version, callbacks, baseRequestResponse);

                String nistLink = "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cpe=cpe%3A%2Fa%3Aapache%3Atomcat%3A" + version;
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - Apache Tomcat " + version,
                        "J2EEscan identified the remote Servlet Container release; "
                                + "Apache Tomcat  version <b>" + version + "</b>.<br />"
                                + "Potential vulnerabilities for this release are available at:<br />"
                                + "<ul><li>" + nistLink + "</li></ul><br /><br />"
                                + "<b>References</b><br />"
                                + "http://tomcat.apache.org/security.html",
                        "Configure the remote application to correctly manage error pages to avoid information disclosure issues",
                        Risk.Low,
                        Confidence.Certain
                ));
            }

        }

        /**
         *
         * JVM Remote Release Detection
         *
         * Tomcat Manager JVM info
         *
         * <tr>
         * <td class="row-center"><small>Apache Tomcat/6.0.26</small></td>
         * <td class="row-center"><small>1.6.0_18-b18</small></td>
         * <td class="row-center"><small>Sun Microsystems Inc.</small></td>
         * <td class="row-center"><small>Linux</small></td>
         * <td
         * class="row-center"><small>2.6.30.10-105.2.23.fc11.i686.PAE</small></td>
         * <td class="row-center"><small>i386</small></td>
         */
        if (respBody != null && reqInfo.getUrl().getPath().contains("manager/html")) {

            Matcher matcher = JVM_RULE.matcher(respBody);

            if (matcher.find()) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - JVM Remote Release Detection",
                        "J2EEscan identified the remote JVM release <b>" + matcher.group(1) + "</b>",
                        "Verify the Java updates for the release:<ul>"
                                + "<li>Java 1.7 http://www.oracle.com/technetwork/java/javase/7u-relnotes-515228.html</li>"
                                + "<li>Java 1.6 http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html</li>"
                                + "<li>Java 1.5 http://www.oracle.com/technetwork/articles/javase/overview-137139.html</li>"
                                + "</ul>",
                        Risk.Information,
                        Confidence.Certain
                ));
            }
        }
    }
}
