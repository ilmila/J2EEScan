package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HTTPMatcher {

    private static final Pattern SERVICES_PATTERN = Pattern.compile("services/(.*?)\\?wsdl", Pattern.MULTILINE);

    private static final Pattern SERVLET_CLA_PATTERN = Pattern.compile("<servlet-class>(.*?)</servlet-class>", Pattern.DOTALL | Pattern.MULTILINE);

    /**
     * Parse the web.xml J2EE resource, and pretty print servlet classes into
     * the burp report
     *
     * @param webxml content of the web.xml configuration file
     * @return a user friendly list with HTML formatted code, of all servlet
     * classes defined into the web.xml file
     */
    public static String getServletsDescription(String webxml) {
        List<String> servlets = getServletsFromWebDescriptors(webxml);
        String description = "";
        if (servlets.isEmpty()) {
            return description;
        }

        description += "<br /><br />List of remote Java classes used by the application:<br /><ul>";

        for (String servlet : servlets) {
            description += "<li><b>" + servlet + "</b></li>";
        }
        description += "</ul><br /><br />It's possible to download the above classes "
                + "located in <i>WEB-INF/classes/</i> folder";
        return description;
    }

    /**
     * Parse the servlet classes from a web.xml file
     *
     * @param webxml content of the web.xml configuration file
     * @return list of servlet classes defined into the web.xml file
     */
    public static List<String> getServletsFromWebDescriptors(String webxml) {
        List<String> servlets = new ArrayList();


        Matcher matcher = SERVLET_CLA_PATTERN.matcher(webxml);
        while (matcher.find()) {
            int numEntries = matcher.groupCount();
            for (int i = 1; i <= numEntries; i++) {
                servlets.add(matcher.group(i).trim().replace("\n", "").replace("\r", ""));
            }
        }

        return servlets;
    }

    /**
     * From the Apache Axis Service Page, parse and retrieve the available web
     * services installed on the remote system
     *
     * @param axisServiceListPage the content of Apache Axis Services page
     * @return a list with the names of all Apache Axis Services
     */
    public static List<String> getServicesFromAxis(String axisServiceListPage) {
        List<String> wsName = new ArrayList();

        Matcher matcher = SERVICES_PATTERN.matcher(axisServiceListPage);
        while (matcher.find()) {
            int numEntries = matcher.groupCount();
            for (int i = 1; i <= numEntries; i++) {
                wsName.add(matcher.group(i).trim().replace("\n", "").replace("\r", ""));
            }
        }

        return wsName;
    }

    public static Boolean isXML(String value) {
        if (value == null) {
            return false;
        }
        return value.trim().startsWith("<");
    }

    /**
     * Helper method to search a response for occurrences of a literal match
     * string and return a list of start/end offsets
     */
    public static List<int[]> getMatches(byte[] response, byte[] match, IExtensionHelpers helpers) {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1) {
                break;
            }
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }

        return matches;
    }

    public static boolean isEtcPasswdFile(byte[] response, IExtensionHelpers helpers) {
        final byte[] PASSWD_PATTERN = "root:".getBytes();
        List<int[]> matchesPasswd = getMatches(response, PASSWD_PATTERN, helpers);

        return (matchesPasswd.size() > 0);
    }

    public static boolean isEtcShadowFile(byte[] response, IExtensionHelpers helpers) {
        final byte[] SHADOW_PATTERN = "root:".getBytes();
        List<int[]> matchesShadow = getMatches(response, SHADOW_PATTERN, helpers);

        return (matchesShadow.size() > 0);
    }

    public static boolean isWinINI(byte[] response, IExtensionHelpers helpers) {
        final byte[] WIN_INI_PATTERN = "for 16-bit app support".getBytes();
        List<int[]> matchesShadow = getMatches(response, WIN_INI_PATTERN, helpers);

        return (matchesShadow.size() > 0);
    }

    /**
     * WEB-INF/ibm-web-ext.xmi
     */
    public static boolean isIBMWebExtFileWAS6(byte[] response, IExtensionHelpers helpers) {
        final byte[] IBMWEB_PATTERN = "<webappext".getBytes();
        List<int[]> matchesIbmweb = getMatches(response, IBMWEB_PATTERN, helpers);

        return (matchesIbmweb.size() > 0);
    }

    /**
     * WEB-INF/ibm-web-ext.xml
     */
    public static boolean isIBMWebExtFileWAS7(byte[] response, IExtensionHelpers helpers) {
        final byte[] IBMWEB_PATTERN = "<web-ext".getBytes();
        List<int[]> matchesIbmweb = getMatches(response, IBMWEB_PATTERN, helpers);

        return (matchesIbmweb.size() > 0);
    }

    /**
     * WEB-INF/ibm-ws-bnd.xml
     */
    public static boolean isIBMWSBinding(byte[] response, IExtensionHelpers helpers) {
        final byte[] IBMWEB_PATTERN = "<webservices-bnd".getBytes();
        List<int[]> matchesIbmweb = getMatches(response, IBMWEB_PATTERN, helpers);

        return (matchesIbmweb.size() > 0);
    }

    public static boolean isApacheStrutsConfigFile(byte[] response, IExtensionHelpers helpers) {
        final byte[] STRUTS_PATTERN = "<struts".getBytes();
        List<int[]> matchesStruts = getMatches(response, STRUTS_PATTERN, helpers);

        return (matchesStruts.size() > 0);
    }

    public static boolean isSpringContextConfigFile(byte[] response, IExtensionHelpers helpers) {
        final byte[] SPRING_PATTERN = "<beans".getBytes();
        List<int[]> matchesStruts = getMatches(response, SPRING_PATTERN, helpers);

        return (matchesStruts.size() > 0);
    }

    public static boolean isWebLogicFile(byte[] response, IExtensionHelpers helpers) {
        final byte[] WEBLOGIC_PATTERN = "<weblogic-web-app".getBytes();
        List<int[]> matchesWebLogic = getMatches(response, WEBLOGIC_PATTERN, helpers);

        return (matchesWebLogic.size() > 0);
    }

    public static boolean isWebDescriptor(byte[] response, IExtensionHelpers helpers) {
        final byte[] WEBXML_PATTERN = "<web-app".getBytes();
        List<int[]> matchesWebDescriptor = getMatches(response, WEBXML_PATTERN, helpers);

        return (matchesWebDescriptor.size() > 0);
    }

    /**
     * Detect the application context of the given URL
     *
     * Ex: http://www.example.org/myapp/test.jsf
     *
     * returns myapp
     */
    public static String getApplicationContext(URL url) {

        String host = url.getHost();
        String protocol = url.getProtocol();
        String path = url.getPath();
        int port = url.getPort();

        int i = path.indexOf("/", 1);
        String context = path.substring(0, i + 1);

        return context;
    }

    /**
     * Iterate on a list of URIs paths and apply some modifiers to 
     * circumvent some weak ACL protections or weak/wrong mod_rewrite rules.
     *
     * Example: * CWE-50: Path Equivalence: '//multiple/leading/slash' *
     * https://cwe.mitre.org/data/definitions/50.html
     *
     */
    public static List URIMutator(List<String> uripaths) {
        List<String> modifiedPaths = new ArrayList<>();
        modifiedPaths.addAll(uripaths);

        for (int i = 0; i < uripaths.size(); i += 1) {
            modifiedPaths.set(i, "/" + uripaths.get(i));
        }
            
            
        return modifiedPaths;
    }
}
