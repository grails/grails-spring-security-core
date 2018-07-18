package grails.plugin.springsecurity.web.filter;

import groovy.transform.CompileStatic;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@CompileStatic
class HttpMethodOverrideDetector {

    /** Default method parameter: <code>_method</code> */
    public static final String DEFAULT_METHOD_PARAM = "_method";

    private String methodParam = DEFAULT_METHOD_PARAM;
    public static final String HEADER_X_HTTP_METHOD_OVERRIDE = "X-HTTP-Method-Override";

    /**
     * Set the parameter name to look for HTTP methods.
     * @see #DEFAULT_METHOD_PARAM
     */
    public void setMethodParam(String methodParam) {
        Assert.hasText(methodParam, "'methodParam' must not be empty");
        this.methodParam = methodParam;
    }

    public String getHttpMethodOverride(HttpServletRequest request) {
        String httpMethod = request.getParameter(methodParam);

        if (httpMethod == null) {
            httpMethod = request.getHeader(HEADER_X_HTTP_METHOD_OVERRIDE);
        }
        return httpMethod == null ? null : httpMethod.toUpperCase();
    }

}
