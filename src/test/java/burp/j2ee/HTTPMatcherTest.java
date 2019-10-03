package burp.j2ee;

import burp.HTTPMatcher;
import static burp.HTTPMatcher.URIMutator;
import static burp.HTTPMatcher.isJavaApplicationByURL;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import junit.framework.TestCase;


public class HTTPMatcherTest extends TestCase {

    public HTTPMatcherTest(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of getApplicationContext method, of class HTTPMatcher.
     */
    public void testGetApplicationContext() throws MalformedURLException {
        System.out.println("getApplicationContext");
        URL url = new URL("http://www.example.org/myapp/Login.jsf?test=1234");
        String expResult = "/myapp/";
        String result = HTTPMatcher.getApplicationContext(url);
        assertEquals(expResult, result);

        System.out.println("getApplicationContext");
        URL url2 = new URL("http://www.example.org/");
        String expResult2 = "";
        String result2 = HTTPMatcher.getApplicationContext(url2);
        assertEquals(expResult2, result2);

        URL url3 = new URL("http://www.example.org/myapp/test/test.jsf");
        String expResult3 = "/myapp/";
        String result3 = HTTPMatcher.getApplicationContext(url3);
        assertEquals(expResult3, result3);
    }

     /**
     * Test of getApplicationContext method, of class HTTPMatcher.
     */
    public void testGetApplicationContextAndNestedPath() throws MalformedURLException {
        System.out.println("getApplicationContextAndNestedPath");
        URL url = new URL("http://www.example.org/myapp/assets/Login.jsf?test=1234");
        String expResult = "/myapp/assets/";
        String result = HTTPMatcher.getApplicationContextAndNestedPath(url);
        assertEquals(expResult, result);

        URL url2 = new URL("http://www.example.org/myapp/");
        String expResult2 = "";
        String result2 = HTTPMatcher.getApplicationContextAndNestedPath(url2);
        assertEquals(expResult2, result2);

        URL url3 = new URL("http://www.example.org/myapp/test/test.jsf");
        String expResult3 = "/myapp/test/";
        String result3 = HTTPMatcher.getApplicationContextAndNestedPath(url3);
        assertEquals(expResult3, result3);
     
        URL url4 = new URL("http://www.example.org/static/js/a.js");
        String expResult4 = "/static/js/";
        String result4 = HTTPMatcher.getApplicationContextAndNestedPath(url4);
        assertEquals(expResult4, result4);
    }
    
    public void testGetServletsFromWebDescriptors() {

        System.out.println("Testing testGetServletsFromWebDescriptors");
        String webxml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<web-app id=\"WebApp_ID\" version=\"2.4\" xmlns=\"http://java.sun.com/xml/ns/j2ee\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd\">\n"
                + "	<display-name>amb_wsoc7</display-name>\n"
                + "	\n"
                + "\n"
                + "	<servlet>\n"
                + "		<servlet-name>SourceID-SSO-Manager</servlet-name>\n"
                + "		<servlet-class>it.test.sso.idp.servlet.IDPManager</servlet-class>\n"
                + "		<load-on-startup>1</load-on-startup>\n"
                + "	</servlet>\n"
                + "	<servlet>\n"
                + "		<servlet-name>logincontroller</servlet-name>\n"
                + "		<servlet-class>it.test.sso.idp.servlet.LoginController</servlet-class>\n"
                + "		<init-param>\n"
                + "			<param-name>homePage</param-name>\n"
                + "			<param-value>/HomePage.jsp</param-value>\n"
                + "		</init-param>\n"
                + "	</servlet>\n"
                + "	<servlet>";

        List servlets = HTTPMatcher.getServletsFromWebDescriptors(webxml);
        System.out.println(servlets.toString());
        assertTrue(servlets.size() == 2);

        String webxml2 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        List servlets2 = HTTPMatcher.getServletsFromWebDescriptors(webxml2);
        assertTrue(servlets2.isEmpty());

        String webxml3 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<web-app id=\"WebApp_ID\" version=\"2.4\" xmlns=\"http://java.sun.com/xml/ns/j2ee\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd\">\n"
                + "	<display-name>example</display-name>\n"
                + "	<servlet>\n"
                + "		<servlet-name>logincontroller</servlet-name>\n"
                + "		<servlet-class>\n"
                + "it.test.sso.idp.servlet.LoginController\n"
                + ""
                + ""
                + "</servlet-class>\n"
                + "		<init-param>\n"
                + "			<param-name>homePage</param-name>\n"
                + "			<param-value>/HomePage.jsp</param-value>\n"
                + "		</init-param>\n"
                + "	</servlet>\n"
                + "	<servlet>";

        List servlets3 = HTTPMatcher.getServletsFromWebDescriptors(webxml3);
        assertTrue(servlets3.size() == 1);
        assertTrue(servlets3.get(0).equals("it.test.sso.idp.servlet.LoginController"));
    }

    public void testGetServicesFromAxis() {

        String axisServiceList = "<h2><font color=\"blue\"><a href=\"http://www.example.com/axis2/services/PayAt?wsdl\">PayAt</a></font></h2>\n"
                + "<font color=\"blue\">Service EPR : </font><font color=\"black\">http://www.example.com/axis2/services/PayAt</font><br>\n"
                + "\n"
                + "\n"
                + "<h4>Service Description : <font color=\"black\">PayAt</font></h4>\n"
                + "<i><font color=\"blue\">Service Status : Active</font></i><br>\n"
                + "<i>Available Operations</i><ul><li>PayAccount</li>\n"
                + "    \n"
                + "    <li>ConfirmPayment</li>\n"
                + "    \n"
                + "    </ul>\n"
                + "<h2><font color=\"blue\"><a href=\"http://www.example.com/axis2/services/PicknPay?wsdl\">PicknPay</a></font></h2>\n"
                + "<font color=\"blue\">Service EPR : </font><font color=\"black\">http://www.example.com/axis2/services/PicknPay</font><br>\n"
                + "\n";
        List wsNames = HTTPMatcher.getServicesFromAxis(axisServiceList);

        System.out.println(wsNames.toString());
        assertTrue(wsNames.size() == 2);
        assertTrue(wsNames.get(0).equals("PayAt"));
        assertTrue(wsNames.get(1).equals("PicknPay"));
    }


    public void testApplicationTypeByURL() throws MalformedURLException {
     
        assertTrue(isJavaApplicationByURL(new URL("http://localhost/")));
        assertTrue(isJavaApplicationByURL(new URL("http://localhost/test.do")));
        assertTrue(isJavaApplicationByURL(new URL("http://localhost/myapp/test?do.php#.do")));
        assertFalse(isJavaApplicationByURL(new URL("http://localhost/myapp/test.php?do.php#.do")));
    }
    
    
    public void testApplicationMutator() throws MalformedURLException {
        List<String> paths = new ArrayList<>();
        paths.add("/");
        paths.add("/admin/private");
        paths.add("/web-console/status?full=true");
        paths.add("/private/test/admin/login.jsp");
                
        List mutateURIs = URIMutator(paths);
        System.out.println(mutateURIs);
        assertTrue(mutateURIs.contains("/admin;/private"));
        assertTrue(mutateURIs.contains("//admin/private"));
        assertTrue(mutateURIs.contains("//admin//private"));
        assertTrue(mutateURIs.contains("//web-console/status?full=true"));
        assertTrue(mutateURIs.contains("//web-console//status?full=true"));
        assertTrue(mutateURIs.contains("/web-console;/status?full=true"));
        
        assertTrue(mutateURIs.contains("/%c0%afprivate/test/admin/login.jsp"));
        assertTrue(mutateURIs.contains("/private/%c0%aftest/admin/login.jsp"));
        assertTrue(mutateURIs.contains("/private/test/%c0%afadmin/login.jsp"));
        assertTrue(mutateURIs.contains("/private/test/admin/%c0%aflogin.jsp"));

        assertTrue(mutateURIs.contains("/%2fprivate/test/admin/login.jsp"));
        assertTrue(mutateURIs.contains("/private/%2ftest/admin/login.jsp"));
        assertTrue(mutateURIs.contains("/private/test/%2fadmin/login.jsp"));
        assertTrue(mutateURIs.contains("/private/test/admin/%2flogin.jsp"));
        
        assertTrue(mutateURIs.contains("/"));
        assertTrue(mutateURIs.contains("/admin/private"));
        assertTrue(mutateURIs.contains("/private/test/admin/login.jsp"));
        assertTrue(mutateURIs.contains("/web-console/status?full=true"));
        
        
    }
}
