package burp.j2ee.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 
 * Custom annotation to mark those modules which should be executed only once
 * for every application context.
 * 
 * This strategy reduce the scan time execution and avoid duplicate checks on the remote target
 * 
 */
@Target(value = ElementType.METHOD)
@Retention(value = RetentionPolicy.RUNTIME)
public @interface RunOnlyOnceForApplicationContext {

}