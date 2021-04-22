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
import burp.IScanIssue;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;

public class LiferayRule implements PassiveRule {


    private boolean isLiferay(IBurpExtenderCallbacks callbacks, String host, String protocol, int port){
        
        for(IScanIssue i : callbacks.getScanIssues("")){            
            if(i.getHttpService().getHost().equals(host) &&
                i.getHttpService().getPort() == port &&
                i.getHttpService().getProtocol().equals(protocol) &&
                i.getIssueName().equals("J2EEScan - Liferay detected"))
                return true;
        }

        return false;
    }


    @Override
    public void scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse,
                     String reqBody, String respBody, IRequestInfo reqInfo, IResponseInfo respInfo,
                     String httpServerHeader, String contentTypeResponse, String xPoweredByHeader){

        List<String> strHeader = respInfo.getHeaders();
        String version = "Not determinable";
        Pattern p = Pattern.compile("Liferay\\s.*\\d\\.\\d\\.\\d.*"); 
        Matcher m;

        IHttpService httpService = baseRequestResponse.getHttpService();
        String host = httpService.getHost(), protocol = httpService.getProtocol();
        int port = httpService.getPort();

        if(isLiferay(callbacks, host, protocol, port)){
            return;
        }

        Iterator<String> iterator = strHeader.iterator();

        while(iterator.hasNext()){
            String s = iterator.next();
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
                                            "Version: " + version, 
                                            "", 
                                            Risk.Information, 
                                            Confidence.Certain));
                
                break;
            }
        }

    }

}