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

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse) {
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

                String nistLink = "http://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cpe=cpe%3A%2Fa%3Aapache%3Atomcat%3A" + version;
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - Apache Tomcat " + version,
                        "J2EEscan identified the remote Servlet Container release; "
                                + "Apache Tomcat  version <b>" + version + "</b>.<br />"
                                + "The potential vulnerabilities for this release are available at:<br />"
                                + "<ul><li>" + nistLink + "</li></ul><br /><br />"
                                + "<b>References</b><br />"
                                + "http://tomcat.apache.org/security.html",
                        "Configure the remote application to correctly manage error pages to avoid information disclosure issues",
                        Risk.Low,
                        Confidence.Certain
                ));
            }

        }
    }
}
