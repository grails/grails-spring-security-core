package grails.plugin.springsecurity.web.filter

import groovy.transform.CompileStatic
import org.springframework.util.Assert

import jakarta.servlet.http.HttpServletRequest

@CompileStatic
class HttpMethodOverrideDetector {

    /** Default method parameter: <code>_method</code> */
    public static final String DEFAULT_METHOD_PARAM = "_method"

    private String methodParam = DEFAULT_METHOD_PARAM
    public static final String HEADER_X_HTTP_METHOD_OVERRIDE = "X-HTTP-Method-Override"

    /**
     * Set the parameter name to look for HTTP methods.
     * @see #DEFAULT_METHOD_PARAM
     */
    void setMethodParam(String methodParam) {
        Assert.hasText(methodParam, "'methodParam' must not be empty")
        this.methodParam = methodParam
    }

    String getHttpMethodOverride(HttpServletRequest request) {
        String httpMethod = request.getParameter(methodParam)

        if (httpMethod == null) {
            httpMethod = request.getHeader(HEADER_X_HTTP_METHOD_OVERRIDE)
        }
        return httpMethod == null ? null : httpMethod.toUpperCase()
    }

}
