    package burp;

import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import java.util.Arrays;
import java.util.List;


/**
 * Knowledge Base to push vulnerabilities based on the remote version detected
 * 
 * 
 */
public class SoftwareVersions {

    public static void getIssues(
            String software,
            String release,
            IBurpExtenderCallbacks callbacks,
            IHttpRequestResponse baseRequestResponse) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);

        
        /**
         * Apache Tomcat
         */
        if (software.equalsIgnoreCase("Apache Tomcat")) {

            /**
             * End of Life - Apache Tomcat
             */
            List<Integer> vulnerableTomcatReleases;
            vulnerableTomcatReleases = Arrays.asList(4, 5, 6, 8);
            if ( vulnerableTomcatReleases.contains(Integer.parseInt(release.substring(0, 1)))) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        requestInfo.getUrl(),
                        baseRequestResponse,
                        "End of Life Software - Apache Tomcat " + release,
                        "J2EEScan identified an unsupported release of Apache Tomcat <b>" + release + "</b>.<br />"
                        + "No more security updates for this version will be released by Apache <br /><br />"
                        + "<b>References</b><br />"
                        + "http://tomcat.apache.org/tomcat-55-eol.html<br />"
                        + "https://tomcat.apache.org/tomcat-60-eol.html<br />"
                        + "https://tomcat.apache.org/tomcat-80-eol.html",
                        "Update the Apache Servlet Container with the last stable release",
                        Risk.High,
                        Confidence.Certain
                ));
            }
        }
        
        
        
        /**
         * Jetty
         */
        if (software.equalsIgnoreCase("Jetty")) {

            /**
             * End of Life - Jetty
             */
            if ( Integer.parseInt(release.substring(0, 1)) < 9 ) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        requestInfo.getUrl(),
                        baseRequestResponse,
                        "End of Life Software - Jetty " + release,
                        "J2EEScan identified an unsupported release of Jetty <b>" + release + "</b>.<br />"
                        + "No more security updates for this version will be released by the vendor <br /><br />"
                        + "<b>References</b><br />"
                        + "https://wiki.eclipse.org/Jetty/Starting/Jetty_Version_Comparison_Table<br />",
                        "Update the Jetty Container with the last stable release",
                        Risk.High,
                        Confidence.Certain
                ));
            }
        }
        
        
        /**
         * Oracle Application Server
         */
        if (software.equalsIgnoreCase("Oracle Application Server")) {

            /**
             * End of Life - Oracle Application Server
             */
            if (release.startsWith("9.") || release.startsWith("10.1.2")) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        requestInfo.getUrl(),
                        baseRequestResponse,
                        "End of Life Software - Oracle Application Server " + release,
                        "J2EEScan identified an unsupported release of Oracle Application Server <b>" + release + "</b>.<br />"
                        + "No more security updates for this version will be released by the vendor <br /><br />"
                        + "<b>References</b><br />"
                        + "http://www.oracle.com/us/support/library/lifetime-support-middleware-069163.pdf<br />",
                        "Update the Oracle Application Server with the last stable release",
                        Risk.High,
                        Confidence.Tentative
                ));
            }
        }
        
        
        
        
    }
}
