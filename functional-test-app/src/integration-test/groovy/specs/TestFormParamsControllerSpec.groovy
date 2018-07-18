package specs

import grails.plugins.rest.client.RestBuilder
import grails.plugins.rest.client.RestResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.RestTemplate
import spock.lang.IgnoreIf
import spock.lang.Issue

/**
 * Please note, these tests utilize the filterChain.chainMap pattern of:
 * [pattern: '/**', filters: 'JOINED_FILTERS,-exceptionTranslationFilter']
 */
@IgnoreIf({ System.getProperty('TESTCONFIG') != 'putWithParams' })
@Issue('https://github.com/grails-plugins/grails-spring-security-core/issues/554')
class TestFormParamsControllerSpec extends AbstractSecuritySpec {

    private final String USERNAME = "Admin"
    private final String PASSWORD = "myPassword"

    void 'PUT request with no parameters'() {
        given:
        RestBuilder restBuilder = new RestBuilder()

        when: "A PUT request with no parameters is made"
        RestResponse response = restBuilder.put("http://localhost:${serverPort}/testFormParams/permitAll") {
            contentType("application/x-www-form-urlencoded")
        }

        then: "the controller responds with the correct status and parameters are null"
        response.status == HttpStatus.OK.value()
        response.text == "username: null, password: null"
    }

    void 'PUT request with parameters in the URL'() {
        given:
        RestBuilder restBuilder = new RestBuilder()

        when: "A PUT request with no parameters is made"
        RestResponse response = restBuilder.put("http://localhost:${serverPort}/testFormParams/permitAll?username=${USERNAME}&password=${PASSWORD}") {
            contentType("application/x-www-form-urlencoded")
        }

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK.value()
        response.text == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PUT request with parameters as x-www-form-urlencoded'() {
        given: "a RestBuilder"
        RestBuilder restBuilder = new RestBuilder()

        and: "a form with username and password params"
        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>()
        form.add("username", USERNAME)
        form.add("password", PASSWORD)

        when: "A PUT request with form params is made"
        RestResponse response = restBuilder.put("http://localhost:${serverPort}/testFormParams/permitAll") {
            contentType("application/x-www-form-urlencoded")
            body(form)
        }

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK.value()
        response.text == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PUT request with NULL Content-Type and parameters in the URL'() {
        given:
        RestBuilder restBuilder = new RestBuilder()

        when: "A PUT request with no parameters is made"
        RestResponse response = restBuilder.put("http://localhost:${serverPort}/testFormParams/permitAll?username=${USERNAME}&password=${PASSWORD}")

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK.value()
        response.text == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PUT request with NULL Content-Type'() {
        given:
        RestBuilder restBuilder = new RestBuilder()

        when: "A PUT request with NULL Content-Type is made"
        RestResponse response = restBuilder.put("http://localhost:${serverPort}/testFormParams/permitAll")

        then: "the controller responds with the correct status and parameters are null"
        response.status == HttpStatus.OK.value()
        response.text == "username: null, password: null"
    }

    void 'PATCH request with no parameters'() {
        given: "An HTTP client that supports PATCH requests"
        RestTemplate restTemplate = new RestTemplate()
        restTemplate.requestFactory = new HttpComponentsClientHttpRequestFactory()
        RestBuilder restBuilder = new RestBuilder(restTemplate)

        when: "A PATCH request with no parameters is made"
        RestResponse response = restBuilder.patch("http://localhost:${serverPort}/testFormParams/permitAll") {
            contentType("application/x-www-form-urlencoded")
        }

        then: "the controller responds with the correct status and parameters are null"
        response.status == HttpStatus.OK.value()
        response.text == "username: null, password: null"
    }

    void 'PATCH request with parameters in the URL'() {
        given: "An HTTP client that supports PATCH requests"
        RestTemplate restTemplate = new RestTemplate()
        restTemplate.requestFactory = new HttpComponentsClientHttpRequestFactory()
        RestBuilder restBuilder = new RestBuilder(restTemplate)

        when: "A PATCH request with no parameters is made"
        RestResponse response = restBuilder.patch("http://localhost:${serverPort}/testFormParams/permitAll?username=${USERNAME}&password=${PASSWORD}") {
            contentType("application/x-www-form-urlencoded")
        }

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK.value()
        response.text == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PATCH request with parameters as x-www-form-urlencoded'() {
        given: "An HTTP client that supports PATCH requests"
        RestTemplate restTemplate = new RestTemplate()
        restTemplate.requestFactory = new HttpComponentsClientHttpRequestFactory()
        RestBuilder restBuilder = new RestBuilder(restTemplate)

        and: "a form with username and password params"
        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>()
        form.add("username", USERNAME)
        form.add("password", PASSWORD)

        when: "A PATCH request with form params is made"
        RestResponse response = restBuilder.patch("http://localhost:${serverPort}/testFormParams/permitAll") {
            contentType("application/x-www-form-urlencoded")
            body(form)
        }

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK.value()
        response.text == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PUT request to secured endpoint with parameters as x-www-form-urlencoded'() {
        given: "a RestBuilder"
        RestBuilder restBuilder = new RestBuilder()

        and: "a form with username and password params"
        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>()
        form.add("username", USERNAME)
        form.add("password", PASSWORD)

        when: "A PUT request with form params is made to a secured endpoint"
        RestResponse response = restBuilder.put("http://localhost:${serverPort}/testFormParams/permitAdmin") {
            contentType("application/x-www-form-urlencoded")
            body(form)
        }

        then: "the request is not processed by the controller"
        response.status == HttpStatus.INTERNAL_SERVER_ERROR.value()
    }

    void 'PATCH request to secured endpoint with parameters as x-www-form-urlencoded'() {
        given: "An HTTP client that supports PATCH requests"
        RestTemplate restTemplate = new RestTemplate()
        restTemplate.requestFactory = new HttpComponentsClientHttpRequestFactory()
        RestBuilder restBuilder = new RestBuilder(restTemplate)

        and: "a form with username and password params"
        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>()
        form.add("username", USERNAME)
        form.add("password", PASSWORD)

        when: "A PATCH request with form params is made to a secured endpoint"
        RestResponse response = restBuilder.patch("http://localhost:${serverPort}/testFormParams/permitAdmin") {
            contentType("application/x-www-form-urlencoded")
            body(form)
        }

        then: "the request is not processed by the controller"
        response.status == HttpStatus.INTERNAL_SERVER_ERROR.value()
    }

    void 'PATCH request with NULL Content-Type and parameters in the URL'() {
        given: "An HTTP client that supports PATCH requests"
        RestTemplate restTemplate = new RestTemplate()
        restTemplate.requestFactory = new HttpComponentsClientHttpRequestFactory()
        RestBuilder restBuilder = new RestBuilder(restTemplate)

        when: "A PUT request with no parameters is made"
        RestResponse response = restBuilder.patch("http://localhost:${serverPort}/testFormParams/permitAll?username=${USERNAME}&password=${PASSWORD}")

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK.value()
        response.text == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PATCH request with NULL Content-Type'() {
        given: "An HTTP client that supports PATCH requests"
        RestTemplate restTemplate = new RestTemplate()
        restTemplate.requestFactory = new HttpComponentsClientHttpRequestFactory()
        RestBuilder restBuilder = new RestBuilder(restTemplate)

        when: "A PATCH request with NULL Content-Type is made"
        RestResponse response = restBuilder.patch("http://localhost:${serverPort}/testFormParams/permitAll")

        then: "the controller responds with the correct status and parameters are null"
        response.status == HttpStatus.OK.value()
        response.text == "username: null, password: null"
    }

}
