package specs

import grails.plugins.rest.client.RestBuilder
import grails.plugins.rest.client.RestResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.RestTemplate

class TestFormParamsSpec extends AbstractSecuritySpec {
    @Value('${local.server.port}')
    Integer serverPort
    private final String USERNAME = "Admin"
    private final String PASSWORD = "myPassword"

    void 'PUT request with no parameters'() {
        given:
        RestBuilder restBuilder = new RestBuilder()

        when: "A PUT request with no parameters is made"
        RestResponse response = restBuilder.put("http://127.0.0.1:${serverPort}/testFormParams") {
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
        RestResponse response = restBuilder.put("http://127.0.0.1:${serverPort}/testFormParams?username=${USERNAME}&password=${PASSWORD}") {
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
        RestResponse response = restBuilder.put("http://127.0.0.1:${serverPort}/testFormParams") {
            contentType("application/x-www-form-urlencoded")
            body(form)
        }

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK.value()
        response.text == "username: ${USERNAME}, password: ${PASSWORD}"
    }

    void 'PATCH request with no parameters'() {
        given: "An HTTP client that supports PATCH requests"
        RestTemplate restTemplate = new RestTemplate()
        restTemplate.requestFactory = new HttpComponentsClientHttpRequestFactory()
        RestBuilder restBuilder = new RestBuilder(restTemplate)

        when: "A PATCH request with no parameters is made"
        RestResponse response = restBuilder.patch("http://127.0.0.1:${serverPort}/testFormParams") {
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
        RestResponse response = restBuilder.patch("http://127.0.0.1:${serverPort}/testFormParams?username=${USERNAME}&password=${PASSWORD}") {
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
        RestResponse response = restBuilder.patch("http://127.0.0.1:${serverPort}/testFormParams") {
            contentType("application/x-www-form-urlencoded")
            body(form)
        }

        then: "the controller responds with the correct status and parameters are extracted"
        response.status == HttpStatus.OK.value()
        response.text == "username: ${USERNAME}, password: ${PASSWORD}"
    }

}
