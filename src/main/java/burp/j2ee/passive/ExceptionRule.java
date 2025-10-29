package burp.j2ee.passive;

import burp.HTTPMatcher;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;

import java.util.Arrays;
import java.util.List;

public class ExceptionRule implements PassiveRule {


    public static final String REMEDY_J2EE_ERROR_HANDLING = "Implement a standard exception handling mechanism to intercept all errors<br /><br />"
            + "http://cwe.mitre.org/data/definitions/388.html<br />"
            + "https://www.owasp.org/index.php/Error_Handling<br />";

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse, String xPoweredByHeader) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        byte[] rawResponse = baseRequestResponse.getResponse();

        /**
         * Apache Struts Exceptions
         *
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            byte[] strutsDevMode = "<title>Struts Problem Report</title>".getBytes();
            List<int[]> matchesStrutsDev = HTTPMatcher.getMatches(rawResponse, strutsDevMode, helpers);
            if (matchesStrutsDev.size() > 0) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Apache Struts - DevMode Enabled",
                        "J2EEScan identified an Apache Struts exception. The remote application  is configured for"
                                + " a development enviroment; development mode, or devMode, enables extra\n"
                                + "debugging behaviors and reports to assist developers.",
                        "Disable development mode in production enviroments using "
                                + "the property <i>struts.devMode=false</i><br /><br />"
                                + "http://struts.apache.org/docs/devmode.html",
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }


        /**
         * Apache Tapestry Exceptions
         *
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            byte[] tapestryException = "<h1 class=\"t-exception-report\">An unexpected application exception has occurred.</h1>".getBytes();
            List<int[]> matchesTapestry = HTTPMatcher.getMatches(rawResponse, tapestryException, helpers);
            if (matchesTapestry.size() > 0) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Incorrect Error Handling - Apache Tapestry",
                        "J2EEScan identified an Apache Tapestry exception."
                                + "The remote application does not properly handle application errors, "
                                + "and application stacktraces are displayed to the end user "
                                + "leading to information disclosure vulnerability.<br /><br /><b>References</b><br />"
                                + "http://tapestry.apache.org/overriding-exception-reporting.html<br />"
                                + "http://tapestry.apache.org/tapestry4.1/developmentguide/exceptionpages.html",
                        REMEDY_J2EE_ERROR_HANDLING,
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }



        /**
         * Grails Exceptions
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            byte[] grailsException = "<h1>Grails Runtime Exception</h1>".getBytes();
            List<int[]> matchesGrails = HTTPMatcher.getMatches(rawResponse, grailsException, helpers);
            if (matchesGrails.size() > 0) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Incorrect Error Handling - Grails",
                        "J2EEScan identified a Grails exception."
                                + "The remote application does not properly handle application errors, "
                                + "and application stacktraces are displayed to the end user "
                                + "leading to information disclosure vulnerability.<br /><br /><b>References</b><br />"
                                + "http://grails.org/plugin/errors",
                        REMEDY_J2EE_ERROR_HANDLING,
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }


        /**
         * GWT Exception
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            byte[] gwtException = "com.google.gwt.http.client.RequestException".getBytes();
            List<int[]> matchesGWT = HTTPMatcher.getMatches(rawResponse, gwtException, helpers);
            if (matchesGWT.size() > 0) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        baseRequestResponse,
                        "Incorrect Error Handling - GWT",
                        "J2EEScan identified a GWT exception."
                                + "The remote application does not properly handle application errors, "
                                + "and application stacktraces are displayed to the end user "
                                + "leading to information disclosure vulnerability.<br /><br /><b>References</b><br />"
                                + "http://www.gwtproject.org/doc/latest/tutorial/RPC.html",
                        REMEDY_J2EE_ERROR_HANDLING,
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }

        /**
         * J2EE Exception
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            List<byte[]> javaxServletExceptions = Arrays.asList(
                    "javax.servlet.ServletException".getBytes(),
                    "onclick=\"toggle('full exception chain stacktrace".getBytes(),
                    "at org.apache.catalina".getBytes(),
                    "at org.apache.coyote.".getBytes(),
                    "at org.jboss.seam.".getBytes(),
                    "at org.apache.tomcat.".getBytes(),
                    "<title>JSP Processing Error</title>".getBytes(),  // WAS
                    "The full stack trace of the root cause is available in".getBytes());

            for (byte[] exc : javaxServletExceptions) {

                List<int[]> matchesJavax = HTTPMatcher.getMatches(rawResponse, exc, helpers);
                if (matchesJavax.size() > 0) {

                    callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            reqInfo.getUrl(),
                            baseRequestResponse,
                            "Incorrect Error Handling - Java",
                            "J2EEScan identified a Java exception. The remote application does not properly handle application errors, "
                                    + "and application stacktraces are displayed to the end user "
                                    + "leading to information disclosure vulnerability",
                            REMEDY_J2EE_ERROR_HANDLING,
                            Risk.Low,
                            Confidence.Certain
                    ));
                }

            }
        }


        /**
         * Java Server Faces Exceptions
         *
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            List<byte[]> jsfExceptions = Arrays.asList(
                    "<pre><code>com.sun.facelets.FaceletException".getBytes(),
                    "Generated by MyFaces - for information on disabling".getBytes(),
                    "<title>Error - org.apache.myfaces".getBytes(),
                    "org.primefaces.webapp".getBytes());

            for (byte[] jsfException : jsfExceptions) {

                List<int[]> matchesJsf = HTTPMatcher.getMatches(rawResponse, jsfException, helpers);
                if (matchesJsf.size() > 0) {

                    callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            reqInfo.getUrl(),
                            baseRequestResponse,
                            "Incorrect Error Handling - JSF",
                            "J2EEScan identified a Java exception. The remote application does not properly handle application errors, "
                                    + "and application stacktraces are displayed to the end user "
                                    + "leading to information disclosure vulnerability",
                            REMEDY_J2EE_ERROR_HANDLING,
                            Risk.Low,
                            Confidence.Certain
                    ));
                }
            }
        }
    }

}
