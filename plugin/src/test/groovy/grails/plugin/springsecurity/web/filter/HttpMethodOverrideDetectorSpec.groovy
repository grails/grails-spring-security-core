package grails.plugin.springsecurity.web.filter

import grails.plugin.springsecurity.AbstractUnitSpec
import org.springframework.http.HttpMethod

class HttpMethodOverrideDetectorSpec extends AbstractUnitSpec {

    public static final String METHOD_PARAM_NAME = 'MeThOd'
    private final HttpMethodOverrideDetector detector = new HttpMethodOverrideDetector()

    void "verify setMethodParam with value"() {
        when:
        detector.setMethodParam(METHOD_PARAM_NAME)

        then:
        detector.methodParam == METHOD_PARAM_NAME
    }

    void "verify setMethodParam with null value"() {
        when:
        detector.setMethodParam(null)

        then:
        thrown IllegalArgumentException
    }

    void "getHttpMethodOverride returns correct http method if http method is set on request params"() {
        given: "a request with a method parameter"
        request.addParameter(detector.DEFAULT_METHOD_PARAM, paramValue)

        when: "getHttpMethodOverride is called"
        String httpMethodOverride = detector.getHttpMethodOverride(request)

        then: "it returns the method from the request parameter"
        httpMethodOverride == paramValue

        where:
        paramValue << [HttpMethod.PATCH.name(), HttpMethod.PUT.name()]
    }

    void "getHttpMethodOverride returns correct http method if http method is set in request header"() {
        given: "the method override header is set to 'TRACE'"
        request.addHeader detector.HEADER_X_HTTP_METHOD_OVERRIDE, HttpMethod.TRACE.name()

        when: "getHttpMethodOverride is called"
        String httpMethodOverride = detector.getHttpMethodOverride(request)

        then: "the method override included in the request header is returned"
        httpMethodOverride == HttpMethod.TRACE.name()
    }

    void "getHttpMethodOverride returns correct http method when http method  is set in both request header and request params"() {
        given: "the method override header is set to 'TRACE'"
        request.addHeader detector.HEADER_X_HTTP_METHOD_OVERRIDE, HttpMethod.TRACE.name()

        and: "the method is set to DELETE in params"
        request.addParameter(detector.DEFAULT_METHOD_PARAM, HttpMethod.DELETE.name())

        when: "getHttpMethodOverride is called"
        String httpMethodOverride = detector.getHttpMethodOverride(request)

        then: "the method override included in the request params is returned"
        httpMethodOverride == HttpMethod.DELETE.name()
    }
}
