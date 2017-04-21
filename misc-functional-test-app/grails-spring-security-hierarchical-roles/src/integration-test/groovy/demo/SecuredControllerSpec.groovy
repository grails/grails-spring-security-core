package demo

import geb.spock.GebSpec
import grails.test.mixin.integration.Integration

@Integration
class SecuredControllerSpec extends GebSpec {

    def setup() {
        browser.baseUrl = "http://localhost:${serverPort}/"
    }

    def "test RoleHierarchyEntry lifecycle"() {
        when:
        to SecuredPage

        then:
        at LoginPage

        when:
        login('sherlock', 'elementary')

        then:
        $().text().contains 'Sorry, you\'re not authorized to view this page.'

        when:
        go 'secured/grantRoleHierarchyEntry'

        then:
        browser.driver.pageSource.contains 'OK'

        when:
        to SecuredPage

        then:
        browser.driver.pageSource.contains 'you have ROLE_ADMIN'
    }
}
