# J2EEScan - J2EE Security Scanner Burp Suite Plugin

[![Join the chat at https://gitter.im/ilmila/J2EEScan](https://badges.gitter.im/ilmila/J2EEScan.svg)](https://gitter.im/ilmila/J2EEScan?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://PayPal.Me/ilmila)



## What is J2EEScan
J2EEScan is a plugin for [Burp Suite Proxy](http://portswigger.net/). 
The goal of this plugin is to improve the test coverage during 
web application penetration tests on J2EE applications. 


## How does it works?

The plugin is fully integrated into the Burp Suite Scanner; it adds some new test 
cases and new strategies to discover different kind of J2EE vulnerabilities.


 ![IMAGE](https://bitbucket.org/ilmila/j2eescan/raw/dev/resources/j2eescan-results.png)


Jetty Version Detection and Remote Leak Shared Buffers vulnerability (CVE-2015-2080)

 ![IMAGE](https://bitbucket.org/ilmila/j2eescan/raw/dev/resources/jetty-remote-leak.png)


Apache Wicket Arbitrary Resource Access (CVE-2015-2080)

 ![IMAGE](https://bitbucket.org/ilmila/j2eescan/raw/dev/resources/wicket.png)



## Test cases:

**Misc**

 * Expression Language Injection (CVE-2011-2730)
 * Apache Roller OGNL Injection (CVE-2013-4212)
 * Local File include - /WEB-INF/web.xml Retrieved
 * Local File Include - Spring Application Context Retrieved
 * Local File Include - struts.xml Retrieved
 * Local File Include - weblogic.xml Retrieved
 * Local File Include - ibm-ws-bnd.xml Retrieved
 * Local File Include - ibm-web-ext.xmi Retrieved
 * Local File Include - ibm-web-ext.xml Retrieved
 * Local File Include - /etc/shadow Retrieved
 * Local File Include - /etc/passwd Retrieved
 * HTTP Auth Weak Password
 * WEB-INF Application Configuration Files Retrieved
 * Status Servlet (CVE-2008-3273)
 * Snoop Servlet (CVE-2012-2170)
 * Extended Path Traversal Scan
 * AJP Service Detection - thanks to [@ikki](https://twitter.com/_ikki)
 * Spring Boot Actuator console
 * UTF8 Response Splitting
 * JK Management Endpoints
 * Pivotal Spring Traversal (CVE-2014-3625)
 
**Apache Struts**

 * Apache Struts 2 S2-023 - thanks to [@h3xstream](https://twitter.com/h3xstream)
 * Apache Struts 2 S2-016
 * Apache Struts 2 S2-017
 * Apache Struts 2 S2-020
 * Apache Struts 2 S2-021
 * Apache Struts 2 S2-032
 * Apache Struts DevMode Enabled
 * Apache Struts OGNL Console

**Grails**

 * Grails Path Traversal (CVE-2014-0053)

**Apache Wicket**
 
 * Apache Wicket Arbitrary Resource Access (CVE-2015-2080)

**Java Server Faces**
 
 * Java Server Faces Local File Include (CVE-2013-3827 CVE-2011-4367)

**JBoss SEAM**

 * JBoss SEAM Remote Command Execution (CVE-2010-1871)

**Incorrect Error Handling**

 * JSF
 * Apache Struts
 * Apache Tapestry
 * Grails
 * GWT
 * Java

**XML Security**
 
 * XInclude Support
 * XML External Entity

**Information Disclosure Issues**

 * Remote JVM version
 * Apache Tomcat version
 * Jetty version
 * Oracle Application Server version
 * Oracle Glassfish version
 * Oracle Weblogic version

**Compliance Checks**
 
 * web.xml - HTTP Verb Tampering
 * web.xml - URL Parameters for Session Tracking
 * web.xml - Incomplete Error Handling
 * web.xml - Invoker Servlet

**JBoss**

 * JBoss Web Service Enumeration
 * JBoss Admin Console Weak Password
 * JBoss JMX/Web Console Not Password Protected
 * JBoss JMX Invoker Remote Command Execution
 * JBoss Undertow Directory Traversal (CVE-2014-7816)
 * JBoss jBPM Admin Console

**Tomcat**

 * Tomcat Manager Console Weak Password
 * Tomcat Host Manager Console Weak Password
 * End Of Life Software - Tomcat

**Weblogic**

 * Weblogic UDDI Explorer Detection
 * Weblogic UDDI Explorer SSRF Vulnerability (CVE-2014-4210)
 * Weblogic Admin Console Weak Password

**Oracle Application Server**
 
 * Added check for Oracle Log Database Accessible
 * Added check for Multiple Oracle Application Server Default Resources (CVE-2002-0565, CVE-2002-0568, CVE-2002-0569)
 * End Of Life Software - Oracle Application Server

**Jetty**

 * Jetty Remote Leak Shared Buffers (CVE-2015-2080) found by [@gdssecurity](https://twitter.com/gdssecurity/)
 * End Of Life Software - Jetty

**Apache Axis**

 * Apache Axis2 - Web Service Enumeration
 * Apache Axis2 - Admin Console Weak Password
 * Apache Axis2 - Local File Include Vulnerability (OSVDB 59001)
 * Apache Axis2 - Happy Axis
 
**NodeJS**

 * NodeJS HTTP Redirect (CVE-2015-1164)
 * NodeJS HTTP Response Splitting (CVE-2016-2216)



## How to install ?

 * From "Cookie jar" section in "Options" -> "Sessions" enable the Scanner field
 * Load the J2EEscan jar in the Burp Extender tab
 * The plugin requires at least Java 1.7


## Contributors:

Special thanks to

  * [@h3xstream](https://twitter.com/h3xstream)
  * [@ikki](https://twitter.com/_ikki)
  * [@Caligin35](https://twitter.com/Caligin35)


## Release Notes


### Version 1.2.5 (29 May, 2016):
 * Added check for UTF8 Response Splitting
 * Added check for JBoss Undertow Directory Traversal (CVE-2014-7816)
 * Added check for NodeJS HTTP Redirect (CVE-2015-1164)
 * Added check for NodeJS HTTP Response Splitting (CVE-2016-2216)
 * Added check for JK Management Endpoints
 * Added check for Pivotal Spring Traversal (CVE-2014-3625)
 * Added check for JBoss jBPM Admin Consoles
 * Adedd check for Apache Struts 2 S2-032 (CVE-2016-3081)
 * Improved LFI payloads
 * Improved EL Injection tests
 * Improved WS Axis security checks


### Version 1.2.4 (26 Nov, 2015):
 * Added check for Spring Boot Actuator console
 * Improved LFI module with new UTF-8 payloads
 * Improved EL Injection with new payloads
 * Added check for Apache Roller OGNL Injection (CVE-2013-4212)
 * Added check for Apache Struts 2 S2-023 - thanks to [@h3xstream](https://twitter.com/h3xstream)
 * Added check for Weblogic Admin Console Weak Password
 * Added check for Oracle Application Server multiple file disclosure issues
 * Added check for Oracle Log Database Accessible
 * Added check for AJP service identification
 * Added check for Weblogic UDDI Explorer SSRF (CVE-2014-4210)
 * Improved performance for passive checks
 * Improved Apache Wicket Information Disclosure
 * Improved J2EE incorrect exception handling
 * Added check for End Of Life Software - Jetty
 * Added check for End Of Life Software - Tomcat
 * Added check for End Of Life Software - Oracle Application Server
 * Added check for Oracle Application Server version
 * Added check for Oracle Glassfish version
 * Added check for Oracle Weblogic version
 * Added check Apache Struts OGNL Console
 * Added check for Happy Axis

 
### Version 1.2.3dev (26 Feb, 2015):
 * Added check for Jetty Remote Leak Shared Buffers (CVE-2015-2080) found by [@gdssecurity](https://twitter.com/gdssecurity/)
 * Improved check for Information Disclosure Issues - Remote JVM version
 * Added check for Apache Wicket Arbitrary Resource Access
 * Added check for Incorrect Error Handling - Apache Tapestry
 * Added check for Incorrect Error Handling - Grails
 * Added check for Incorrect Error Handling - GWT
 * Fixed references for EL Injection issue

### Version 1.2.2dev (23 Feb, 2015):
 * Added check for Information Disclosure Issues - Remote JVM version
 * Added check for Information Disclosure Issues - Apache Tomcat version
 * Added check for weak password on HTTP Authentication
 * Fix some bugs on issues reporting

### Version 1.2.1dev (16 Feb, 2015):
 * Improved LFI checks
 * Added initial support for compliance checks

### Version 1.2 (25 Jan, 2015):
 * Added checks for Apache Axis2
 * Added checks for Jboss Admin Console Weak Password
 * Added checks for Jboss JMX Invoker
 * Added checks for Status Servlet
 * Added checks for Snoop Resources
 * Added checks for Apache Tomcat Host Manager Console
 * Multiple bug fixes
 * Pushed [BApp Store](https://pro.portswigger.net/bappstore/). 

### Version 1.1.2 (18 Oct, 2014):
 * Initial Public Release
 

