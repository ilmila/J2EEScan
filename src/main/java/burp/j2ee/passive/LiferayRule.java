package burp.j2ee.passive;

import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.IssuesHandler;
import burp.j2ee.Risk;

/**
 * This scanner try to identify a Liferay istallation on the system by analyzing the header which usually contains
 * a string relating to the current version. Some examples of these strings are:
 * - Liferay-Portal: Liferay Portal Standard Edition 5.2.3 (Augustine / Build 5203 / May 20, 2009)
 * - Liferay-Portal: Liferay Portal Community Edition 6.2.0 CE GA1 (Newton / Build 6200 / November 1, 2013)
 * - Liferay-Portal: Liferay Portal Community Edition 6.2 CE GA4 (Newton / Build 6203 / April 16, 2015)
 * - Liferay-Portal: Liferay DXP Digital Enterprise 7.0.10 GA1 (Wilberforce / Build 7010 / June 15, 2016)
 * 
 * If the header doesn't contains any string with "Liferay" the body is checked.
 * 
 * This scanner has been tested on the following Liferay versions:
 * - Portal 7.3.6-ga7
 * - Portal 7.2.0-ga1
 * - Portal 7.1.2-ga3
 * - Portal 7.0.3-ga3
 * - DXP 7.3.10-ga1
 */

public class LiferayRule implements PassiveRule {

    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse, String xPoweredByHeader){

        List<String> strHeader = respInfo.getHeaders();
        String version = "Not determinable";
        Pattern p = Pattern.compile("Liferay\\s.*\\d\\.\\d.*"); 
        Matcher m;

        IHttpService httpService = baseRequestResponse.getHttpService();
        String host = httpService.getHost(), protocol = httpService.getProtocol();

        if (IssuesHandler.isvulnerabilityFound(callbacks,
                    "J2EEScan - Liferay detected",
                    protocol,
                    host)) {
                return;
        } 

        Iterator<String> iterator = strHeader.iterator();

        while(iterator.hasNext()){
            String s = iterator.next();

            /**
             * "liferayAUICSS" is the link id for the current theme stylesheet of Liferay, while 
             * "liferayPortalCSS" is also an id but for another stylesheet
             */
            if(s.contains("Liferay") || (!iterator.hasNext() 
                                        && respBody.contains("id=\"liferayAUICSS\"") 
                                        && respBody.contains("id=\"liferayPortalCSS\""))){
                m = p.matcher(s);
                if(m.find()){
                    version = m.group();

                    callbacks.addScanIssue(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            reqInfo.getUrl(), 
                                            baseRequestResponse, 
                                            "Liferay hardening - Information leakage through HTTP response header",
                                            "In the HTTP header returned by Liferay there is a field that leaks the version installed."
                                            + " See 'J2EEScan - Liferay detected' issue for more information", 
                                            "Remove the response HTTP header Liferay-Portal which leaks internal information regarding platform versioning", 
                                            Risk.Low, 
                                            Confidence.Certain));
                }

                callbacks.addScanIssue(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            reqInfo.getUrl(), 
                                            baseRequestResponse, 
                                            "Liferay detected", 
                                            ((version.equals("Not determinable")) 
                                                ? "An installation of liferay has been found" 
                                                : "An installation of liferay has been found with the following version: " + version)
                                            + "<br /><br />Liferay is an open-source enteprise portal written in java. There is a community edition (CE) "
                                            + "and an Enterprise Edition (DXP). Source code of the first one can be found on https://github.com/liferay/liferay-portal"
                                            + "<br /><br /><b>References</b>:<br /><br />"
                                            + "https://www.cvedetails.com/vulnerability-list/vendor_id-2114/Liferay.html<br />"
                                            + "https://www.acunetix.com/vulnerabilities/web/<br />"
                                            + "https://portal.liferay.dev/learn/security/known-vulnerabilities<br />", 
                                            "", 
                                            Risk.Information, 
                                            Confidence.Certain));
                
                break;
            }
        }

    }

}