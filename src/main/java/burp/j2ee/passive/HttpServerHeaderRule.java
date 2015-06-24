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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpServerHeaderRule implements PassiveRule {


    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse) {


        IExtensionHelpers helpers = callbacks.getHelpers();


        /* HTTP Server Header examples
         * Server: Jetty/5.1.x (Linux/2.6.33.5-iR4-1.0.4.3 arm java/1.6.0_21
         * Server: Jetty/5.1.12 (Linux/2.6.18-371.11.1.el5.centos.plus amd64 java/1.6.0_34
         * Server: Jetty/5.1.3 (Windows 2003/5.2 x86 java/1.5.0_09
         */
        if (httpServerHeader != null) {
            Pattern javaRule = Pattern.compile("java\\/([\\d\\.\\_]+)", Pattern.DOTALL);
            Matcher javaMatcher = javaRule.matcher(httpServerHeader);
            if (javaMatcher.find()) {
                String version = javaMatcher.group(1);
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - JVM Remote Release Detection",
                        "J2EEscan identified the remote JVM release <b>" + version + "</b>",
                        "Verify the Java updates for the release:<ul>"
                                + "<li>Java 1.7 http://www.oracle.com/technetwork/java/javase/7u-relnotes-515228.html</li>"
                                + "<li>Java 1.6 http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html</li>"
                                + "<li>Java 1.5 http://www.oracle.com/technetwork/articles/javase/overview-137139.html</li>"
                                + "</ul>",
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }



        /**
         * Detect Jetty
         *
         * HTTP Server Header examples Server: Jetty(6.1.1) Server:
         * Jetty(9.0.4.v20130625) Server: Jetty/5.1.x
         * (Linux/2.6.33.5-iR4-1.0.4.3 arm java/1.6.0_21 Server: Jetty/5.1.12
         * (Linux/2.6.18-371.11.1.el5.centos.plus amd64 java/1.6.0_34 Server:
         * Jetty/5.1.3 (Windows 2003/5.2 x86 java/1.5.0_09
         */
        if (httpServerHeader != null) {
            Pattern jettyRule = Pattern.compile("Jetty.([\\d\\.]+)", Pattern.DOTALL);
            Matcher jettyMatcher = jettyRule.matcher(httpServerHeader);
            if (jettyMatcher.find()) {
                String version = jettyMatcher.group(1);

                SoftwareVersions.getIssues("Jetty", version, callbacks, baseRequestResponse);

                String nistLink = "http://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cpe=cpe%3A%2Fa%3Amortbay%3Ajetty%3A" + version;
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - Jetty " + version,
                        "J2EEscan identified the remote Servlet Container release; "
                                + "Jetty  version <b>" + version + "</b>.<br />"
                                + "The potential vulnerabilities for this release are available at:<br />"
                                + "<ul><li>" + nistLink + "</li></ul><br /><br />",
                        "Configure the remote servlet container to suppress the HTTP Server header using the <i>sendServerVersion</i> directive<br />"
                                + "http://docs.codehaus.org/display/JETTY/How+to+suppress+the+Server+HTTP+header",
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

            Pattern jvmRule = Pattern.compile("\"><small>(1\\.\\d\\.[\\w\\-\\_\\.]+)<", Pattern.DOTALL | Pattern.MULTILINE);
            Matcher matcher = jvmRule.matcher(respBody);

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



        /**
         * Detect Jetty
         *
         * HTTP Server Header examples Server: Jetty(6.1.1) Server:
         * Jetty(9.0.4.v20130625) Server: Jetty/5.1.x
         * (Linux/2.6.33.5-iR4-1.0.4.3 arm java/1.6.0_21 Server: Jetty/5.1.12
         * (Linux/2.6.18-371.11.1.el5.centos.plus amd64 java/1.6.0_34 Server:
         * Jetty/5.1.3 (Windows 2003/5.2 x86 java/1.5.0_09
         */
        if (httpServerHeader != null) {
            Pattern jettyRule = Pattern.compile("Jetty.([\\d\\.]+)", Pattern.DOTALL);
            Matcher jettyMatcher = jettyRule.matcher(httpServerHeader);
            if (jettyMatcher.find()) {
                String version = jettyMatcher.group(1);

                SoftwareVersions.getIssues("Jetty", version, callbacks, baseRequestResponse);

                String nistLink = "http://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cpe=cpe%3A%2Fa%3Amortbay%3Ajetty%3A" + version;
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - Jetty " + version,
                        "J2EEscan identified the remote Servlet Container release; "
                                + "Jetty  version <b>" + version + "</b>.<br />"
                                + "The potential vulnerabilities for this release are available at:<br />"
                                + "<ul><li>" + nistLink + "</li></ul><br /><br />",
                        "Configure the remote servlet container to suppress the HTTP Server header using the <i>sendServerVersion</i> directive<br />"
                                + "http://docs.codehaus.org/display/JETTY/How+to+suppress+the+Server+HTTP+header",
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }

        /**
         * Detect Glassfish
         *
         * HTTP Server Header examples
         *
         * Server: GlassFish Server Open Source Edition 3.1.1 Server: GlassFish
         * Server Open Source Edition 4.0 Server: GlassFish Server Open Source
         * Edition 4.1
         */
        if (httpServerHeader != null) {
            Pattern glassfishRule = Pattern.compile("GlassFish Server Open Source Edition ([\\d\\.]+)", Pattern.DOTALL);
            Matcher glassfishMatcher = glassfishRule.matcher(httpServerHeader);
            if (glassfishMatcher.find()) {
                String version = glassfishMatcher.group(1);

                SoftwareVersions.getIssues("GlassFish", version, callbacks, baseRequestResponse);

                String nistLink = "http://web.nvd.nist.gov/view/vuln/search-results?cpe=cpe%3A%2Fa%3Aoracle%3Aglassfish_server%3A" + version;
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - Glassfish " + version,
                        "J2EEscan identified the remote Application Server release; "
                                + "Glassfish  version <b>" + version + "</b>.<br />"
                                + "The potential vulnerabilities for this release are available at:<br />"
                                + "<ul><li>" + nistLink + "</li></ul><br /><br />",
                        "Configure the remote application server to suppress the HTTP Server header<br />"
                                + "http://blog.eisele.net/2011/05/securing-your-glassfish-hardening-guide.html<br />"
                                + "https://javadude.wordpress.com/2013/12/06/hide-glassfish-server-information/",
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }

        /**
         * Detect WebLogic
         *
         * HTTP Server Header examples
         *
         * Server: WebLogic 5.1.0 Service Pack 13 12/12/2002 22:13:10 #228577
         * Server: WebLogic Server 7.0 SP4 Tue Aug 12 11:22:26 PDT 2003 284033
         * Server: WebLogic Server 8.1 SP3 Tue Jun 29 23:11:19 PDT 2004 404973
         * Server: WebLogic WebLogic Server 7.0 SP2 Sun Jan 26 23:09:32 PST 2003
         * Server: WebLogic WebLogic Server 6.1 SP2 12/18/2001 11:13:46
         *
         */
        if (httpServerHeader != null) {
            Pattern weblogicRule = Pattern.compile("WebLogic (:?Server )?([\\d\\.]+)", Pattern.DOTALL);
            Matcher weblogicMatcher = weblogicRule.matcher(httpServerHeader);
            if (weblogicMatcher.find()) {
                String version = weblogicMatcher.group(2);

                SoftwareVersions.getIssues("WebLogic", version, callbacks, baseRequestResponse);

                String nistLink = "http://web.nvd.nist.gov/view/vuln/search-results?cpe=cpe%3A%2Fa%3Aoracle%3Aweblogic_server%3A" + version;
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - WebLogic " + version,
                        "J2EEscan identified the remote Application Server release; "
                                + "WebLogic  version <b>" + version + "</b>.<br />"
                                + "The potential vulnerabilities for this release are available at:<br />"
                                + "<ul><li>" + nistLink + "</li></ul><br /><br />",
                        "Configure the remote application server to suppress the HTTP Server header<br />",
                        Risk.Information,
                        Confidence.Certain
                ));
            }
        }

        /**
         *
         * Detect Oracle Application Server
         *
         * HTTP Server Header examples
         *
         * Server: Oracle Application Server Containers for J2EE 10g (9.0.4.1.0)
         * Server: Oracle-Application-Server-10g/10.1.2.2.0 Oracle-HTTP-Server
         * Server: Oracle-Application-Server-10g/10.1.3.1.0 Oracle-HTTP-Server
         * Server: Oracle Application Server/10.1.2.3.1
         *
         */
        if (httpServerHeader != null) {
            List<Pattern> oracleApplicationServerRe = new ArrayList();

            oracleApplicationServerRe.add(Pattern.compile("Oracle Application Server Containers for J2EE 10g \\(([\\d\\.]+)\\)", Pattern.DOTALL));
            oracleApplicationServerRe.add(Pattern.compile("Oracle.Application.Server.10g\\/([\\d\\.]+)", Pattern.DOTALL));
            oracleApplicationServerRe.add(Pattern.compile("Oracle Application Server\\/([\\d\\.]+)", Pattern.DOTALL));
            oracleApplicationServerRe.add(Pattern.compile("Oracle9iAS\\/([\\d\\.]+)", Pattern.DOTALL));

            // check the pattern
            for (Pattern oracleRe : oracleApplicationServerRe) {

                Matcher oracleMatcher = oracleRe.matcher(httpServerHeader);
                if (oracleMatcher.find()) {
                    String version = oracleMatcher.group(1);

                    SoftwareVersions.getIssues("Oracle Application Server", version, callbacks, baseRequestResponse);

                    String nistLink = "http://web.nvd.nist.gov/view/vuln/search-results?cpe=cpe%3A%2Fa%3Aoracle%3Aapplication_server%3A" + version;
                    callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            reqInfo.getUrl(),
                            baseRequestResponse,
                            "Information Disclosure - Oracle Application Server " + version,
                            "J2EEscan identified the remote Application Server release; "
                                    + "Oracle Application Server  version <b>" + version + "</b>.<br />"
                                    + "The potential vulnerabilities for this release are available at:<br />"
                                    + "<ul><li>" + nistLink + "</li></ul><br /><br />",
                            "Configure the remote application server to suppress the HTTP Server header<br />"
                                    + "http://docs.oracle.com/cd/E23943_01/web.1111/e10144/faq.htm#HSADM939<br />"
                                    + "https://oamidam.wordpress.com/2011/06/01/controlling-the-server-header-with-oracle-http-server-and-oracle-web-cache-11g/",
                            Risk.Low,
                            Confidence.Certain
                    ));

                    break;
                }
            }

        }

    }
}
