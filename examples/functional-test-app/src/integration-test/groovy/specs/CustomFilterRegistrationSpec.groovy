package specs

import grails.plugin.springsecurity.Application
import grails.testing.mixin.integration.Integration
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import spock.lang.IgnoreIf
import spock.lang.Issue

@IgnoreIf({ System.getProperty('TESTCONFIG') != 'issue503' })
@Issue('https://github.com/grails-plugins/grails-spring-security-core/issues/503')
@Integration(applicationClass = functional.test.app.Application)
class CustomFilterRegistrationSpec extends HttpClientSpec {

    void 'GET request to /assets/spinner.gif should not throw error because custom filter is excluded'() {
        when: "A GET request to the assets directory is made"
        HttpResponse response = client.toBlocking().exchange(HttpRequest.GET("/assets/spinner.gif"))

        then: "the filter is not invoked because of the chainMap defition of filters: 'none' in application.groovy"
        response.status == HttpStatus.OK
    }
}
