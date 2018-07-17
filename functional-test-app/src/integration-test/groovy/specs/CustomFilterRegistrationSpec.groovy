package specs

import grails.plugins.rest.client.RestBuilder
import grails.plugins.rest.client.RestResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import spock.lang.IgnoreIf
import spock.lang.Issue

@IgnoreIf({ System.getProperty('TESTCONFIG') != 'issue503' })
@Issue('https://github.com/grails-plugins/grails-spring-security-core/issues/503')
class CustomFilterRegistrationSpec extends AbstractSecuritySpec {

    @Value('${local.server.port}')
    Integer serverPort

    void 'GET request to /assets/spinner.gif should not throw error because custom filter is excluded'() {
        given: "MaintenanceModeFilter is registered in BootStrap and we have a restBuilder"
        RestBuilder restBuilder = new RestBuilder()

        when: "A GET request to the assets directory is made"
        RestResponse response = restBuilder.get("http://localhost:${serverPort}/assets/spinner.gif")

        then: "the filter is not invoked because of the chainMap defition of filters: 'none' in application.groovy"
        response.status == HttpStatus.OK.value()
    }
}
