package specs

import grails.testing.mixin.integration.Integration
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.uri.UriTemplate
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import spock.lang.IgnoreIf
import spock.lang.Issue

/**
 * Please note, these tests utilize the filterChain.chainMap pattern of:
 * [pattern: '/**', filters: 'JOINED_FILTERS,-exceptionTranslationFilter']
 */
@IgnoreIf({ System.getProperty('TESTCONFIG') != 'putWithParams' })
@Issue('https://github.com/grails-plugins/grails-spring-security-core/issues/554')
@Integration
class TestFormParamsControllerSpec extends HttpClientSpec {

    private final String USERNAME = "Admin"
    private final String PASSWORD = "myPassword"

    void 'PUT request with no parameters'() {
        when: "A PUT request with no parameters is made"
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PUT("/testFormParams/permitAll", "").contentType("application/x-www-form-urlencoded"), String)

        then: "the controller responds with the correct status and parameters are null"
        response.status == HttpStatus.OK
        response.body() == "username: null, password: null"
    }

    void 'PUT request with parameters in the URL'() {
        when: "A PUT request with no parameters is made"
        String expandUrl = new UriTemplate("/testFormParams/permitAll{?username,password}").expand(["username": USERNAME, "password": PASSWORD])
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PUT(expandUrl, "").contentType("application/x-www-form-urlencoded"), String)

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK
        response.body() == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PUT request with parameters as x-www-form-urlencoded'() {
        given: "a form with username and password params"
        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>()
        form.add("username", USERNAME)
        form.add("password", PASSWORD)

        when: "A PUT request with form params is made"
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PUT("/testFormParams/permitAll", form).contentType("application/x-www-form-urlencoded"), String)

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK
        response.body() == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PUT request with NULL Content-Type and parameters in the URL'() {
        when: "A PUT request with no parameters is made"
        String expandUrl = new UriTemplate("/testFormParams/permitAll{?username,password}").expand(["username": USERNAME, "password": PASSWORD])
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PUT(expandUrl, ""), String)

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK
        response.body() == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PUT request with NULL Content-Type'() {
        when: "A PUT request with NULL Content-Type is made"
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PUT("/testFormParams/permitAll", ""), String)

        then: "the controller responds with the correct status and parameters are null"
        response.status == HttpStatus.OK
        response.body() == "username: null, password: null"
    }

    void 'PATCH request with no parameters'() {
        when: "A PATCH request with no parameters is made"
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PATCH("/testFormParams/permitAll", "").contentType("application/x-www-form-urlencoded"), String)

        then: "the controller responds with the correct status and parameters are null"
        response.status == HttpStatus.OK
        response.body() == "username: null, password: null"
    }

    void 'PATCH request with parameters in the URL'() {
        when:
        String expandUrl = new UriTemplate("/testFormParams/permitAll{?username,password}").expand(["username": USERNAME, "password": PASSWORD])
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PATCH(expandUrl, "").contentType("application/x-www-form-urlencoded"), String)

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK
        response.body() == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PATCH request with parameters as x-www-form-urlencoded'() {
        given: "a form with username and password params"
        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>()
        form.add("username", USERNAME)
        form.add("password", PASSWORD)

        when: "A PATCH request with form params is made"
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PATCH("/testFormParams/permitAll", form
        ).contentType("application/x-www-form-urlencoded"), String)

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK
        response.body() == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PUT request to secured endpoint with parameters as x-www-form-urlencoded'() {
        given: "a form with username and password params"
        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>()
        form.add("username", USERNAME)
        form.add("password", PASSWORD)

        when: "A PUT request with form params is made to a secured endpoint"
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PUT("/testFormParams/permitAdmin", form
        ).contentType("application/x-www-form-urlencoded"), String)

        then: "the request is not processed by the controller"
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.INTERNAL_SERVER_ERROR
    }

    void 'PATCH request to secured endpoint with parameters as x-www-form-urlencoded'() {
        given:
        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>()
        form.add("username", USERNAME)
        form.add("password", PASSWORD)

        when: "A PATCH request with form params is made to a secured endpoint"
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PATCH("/testFormParams/permitAdmin", form
        ).contentType("application/x-www-form-urlencoded"), String)

        then: "the request is not processed by the controller"
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.INTERNAL_SERVER_ERROR
    }

    void 'PATCH request with NULL Content-Type and parameters in the URL'() {
        when:
        String expandUrl = new UriTemplate("/testFormParams/permitAll{?username,password}").expand(["username": USERNAME, "password": PASSWORD])
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PATCH(expandUrl, ""
        ).contentType("application/x-www-form-urlencoded"), String)

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK
        response.body() == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PATCH request with NULL Content-Type'() {
        when: "A PATCH request with NULL Content-Type is made"
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.PATCH("/testFormParams/permitAll", ""
        ), String)

        then: "the controller responds with the correct status and parameters are null"
        response.status == HttpStatus.OK
        response.body() == "username: null, password: null"
    }

}
