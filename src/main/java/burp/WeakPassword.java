package burp;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class WeakPassword {

    public final List<Map.Entry<String, String>> credentials;

    public WeakPassword() {
        credentials = new ArrayList<>();
    }

    public void addCredential(Map.Entry<String, String> credential) {
        credentials.add(credential);
    }

    /**
     * Get a list of common username and password couples
     *
     * @return
     */
    public List<Map.Entry<String, String>> getCredentials() {

        credentials.add(new AbstractMap.SimpleEntry<>("tomcat", "tomcat"));
        credentials.add(new AbstractMap.SimpleEntry<>("tomcat", "manager"));
        credentials.add(new AbstractMap.SimpleEntry<>("tomcat", "jboss"));
        credentials.add(new AbstractMap.SimpleEntry<>("tomcat", "password"));
        credentials.add(new AbstractMap.SimpleEntry<>("tomcat", ""));
        credentials.add(new AbstractMap.SimpleEntry<>("both", "manager"));
        credentials.add(new AbstractMap.SimpleEntry<>("both", "tomcat"));
        credentials.add(new AbstractMap.SimpleEntry<>("admin", "password"));
        credentials.add(new AbstractMap.SimpleEntry<>("admin", "tomcat"));
        credentials.add(new AbstractMap.SimpleEntry<>("admin", "manager"));
        credentials.add(new AbstractMap.SimpleEntry<>("manager", "manager"));
        credentials.add(new AbstractMap.SimpleEntry<>("manager", "tomcat"));
        credentials.add(new AbstractMap.SimpleEntry<>("role1", "role1"));
        credentials.add(new AbstractMap.SimpleEntry<>("role1", "tomcat"));
        credentials.add(new AbstractMap.SimpleEntry<>("role", "changethis"));
        credentials.add(new AbstractMap.SimpleEntry<>("root", "changethis"));
        credentials.add(new AbstractMap.SimpleEntry<>("tomcat", "changethis"));
        credentials.add(new AbstractMap.SimpleEntry<>("admin", "j5Brn9")); // Sun Solaris       
        credentials.add(new AbstractMap.SimpleEntry<>("admin", "admin"));
        credentials.add(new AbstractMap.SimpleEntry<>("admin", "root"));
        credentials.add(new AbstractMap.SimpleEntry<>("admin", "password"));
        credentials.add(new AbstractMap.SimpleEntry<>("admin", ""));
        credentials.add(new AbstractMap.SimpleEntry<>("admin", "1234"));
        credentials.add(new AbstractMap.SimpleEntry<>("admin", "axis2"));
        credentials.add(new AbstractMap.SimpleEntry<>("test", "test"));
        credentials.add(new AbstractMap.SimpleEntry<>("monitor", "monitor"));
        credentials.add(new AbstractMap.SimpleEntry<>("guest", "guest"));
        credentials.add(new AbstractMap.SimpleEntry<>("root", ""));
        credentials.add(new AbstractMap.SimpleEntry<>("root", "root"));
        credentials.add(new AbstractMap.SimpleEntry<>("root", "admin"));
        credentials.add(new AbstractMap.SimpleEntry<>("root", "password"));
        credentials.add(new AbstractMap.SimpleEntry<>("weblogic", "weblogic"));
        credentials.add(new AbstractMap.SimpleEntry<>("weblogic", "weblogic1"));
        credentials.add(new AbstractMap.SimpleEntry<>("weblogic", "weblogic01"));
        credentials.add(new AbstractMap.SimpleEntry<>("weblogic", "welcome1"));
        credentials.add(new AbstractMap.SimpleEntry<>("admin", "security"));
        credentials.add(new AbstractMap.SimpleEntry<>("oracle", "oracle"));
        credentials.add(new AbstractMap.SimpleEntry<>("system", "security"));
        credentials.add(new AbstractMap.SimpleEntry<>("system", "password"));
        credentials.add(new AbstractMap.SimpleEntry<>("wlcsystem", "wlcsystem"));
        credentials.add(new AbstractMap.SimpleEntry<>("wlpisystem", "wlpisystem"));
        
        // Orbeon forms
        credentials.add(new AbstractMap.SimpleEntry<>("orbeonadmin", "xforms"));

        return credentials;

    }

}
