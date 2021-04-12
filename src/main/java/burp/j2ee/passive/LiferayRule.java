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

        for(IScanIssue i : callbacks.getScanIssues("")){
            if(i.getHttpService().getHost().equals(host) &&
                i.getHttpService().getPort() == port &&
                i.getHttpService().getProtocol().equals(protocol) &&
                i.getIssueName().equals("Liferay detected"))
                return;
        }

        

        Iterator<String> iterator = strHeader.iterator();

        while(iterator.hasNext()){
            String s = iterator.next();
            if(s.contains("Liferay") || (!iterator.hasNext() 
                                        && respBody.contains("id=\"liferayAUICSS\"") 
                                        && respBody.contains("id=\"liferayPortalCSS\""))){
                m = p.matcher(s);
                if(m.find())
                    version = m.group();
                
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