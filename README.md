# J2EEScan - J2EE Security Scanner Burp Suite Plugin

[![Join the chat at https://gitter.im/ilmila/J2EEScan](https://badges.gitter.im/ilmila/J2EEScan.svg)](https://gitter.im/ilmila/J2EEScan?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://PayPal.Me/ilmila)



## What is J2EEScan
J2EEScan is a plugin for [Burp Suite Proxy](http://portswigger.net/). 
The goal of this plugin is to improve the test coverage during 
web application penetration tests on J2EE applications. 


## How does it works?

The plugin is fully integrated into the Burp Suite Scanner; it adds **more than 80+ unique security test 
cases** and new strategies to discover different kind of J2EE vulnerabilities.


 ![IMAGE](assets/issues-example.png)


## How to install ?

 * From "Cookie jar" section in "Options" -> "Sessions" enable the Scanner and Extender fields
 * Load the J2EEscan jar in the Burp Extender tab
 * The plugin requires at least Java 1.7


## Contributors:

Special thanks to

  * [@h3xstream](https://twitter.com/h3xstream)
  * [@martinbydefault](https://github.com/martinbydefault)
  * [@ikki](https://twitter.com/_ikki)
  * [@Caligin35](https://twitter.com/Caligin35)
  * [@greenfile](https://github.com/greenfile)


## Release Notes

### Version 2.0.0beta.2
 * Added check for AJP Tomcat GhostCat (CVE-2020-1938)
 * Improve detection for Apache Tomcat EoL 
 * Improved Jackson CVE-2017-7525 deserialization flaw
 * Improved EL Injection detection to minimize FP
 * Improved JBoss Seam 2 Remote Command Execution (thanks to https://github.com/greenfile)
 * Added check for Spring Cloud Path Traversal CVE-2020-5410

### Version 2.0.0beta (9 Jan, 2020):
 * Major improved on scan time performance
 * Added check for Spring Data Commons Remote Code Execution (CVE-2018-1273)
 * Added check for PrimeFaces Expression Language Injection (CVE-2017-1000486)
 * Added check for Spring Data REST - Remote Command Execution (CVE-2017-8046)
 * Added check for Eclipse Mojarra Path Traversal (CVE-2018-14371)
 * Added check for Tomcat URI Normalization found by [@orange_8361](https://twitter.com/orange_8361)
 * Added check for Fastjson RCE (CVE-2017-7525)
 * Added check for Apache SOLR (CVE-2017-12629)
 * Added check for EL3 Injection
 * Added check for Apache Struts Showcase
 * Added check for Apache Struts2 S2-043
 * Added check for Apache Struts2 S2-052
 * Added strategy to bypass weak ACL URI restrictions
 * Added check for SSRF Scanner
 * Added check for REST API Swagger Scanner
 * Added check for Oracle EBS SSRF Vulnerabilities (CVE-2018-3167, CVE-2017-10246)
 * Added check for Next.js Path Traversal Vulnerability (CVE-2018-6184)
 * Added check for NodeJs Path Traversal (2017-14849)
 * Added check check for Session Fixation
 * Added check for session id in url
 * Added check for Javascript PostMessage detection
 * Added check for JBoss HTTP Invoker ReadOnlyAccessFilter CVE-2017-12149
 * Added check for NodeJS Path Traversal CVE-2017-14849
 * Added check for new base check for EL issue
 * Added check for JBoss WS JUDDI console
 * Added check for Oracle iDOC Injection (CVE-2013-3770)
 * Added check for HTTP Open Proxy Detection
 * Improved detection for XXE attacks on xml parameters
 * Improved detection on local file include/path traversal on J2EE env
 * Improve detection for CVE-2014-3625 - Spring Directory Traversal
 * Improve detection for LFI attacks
 * Improve detection for Java Server Faces Path Traversal
 * Improved detection for Infrastructural Path Traversal
 * Improved Spring Boot Actuator
 * Improved check for Apache Axis Admin Console


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
 

