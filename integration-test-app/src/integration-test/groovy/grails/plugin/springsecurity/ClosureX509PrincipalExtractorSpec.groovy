package grails.plugin.springsecurity

import grails.plugin.springsecurity.web.authentication.preauth.x509.ClosureX509PrincipalExtractor
import org.springframework.security.authentication.BadCredentialsException

import java.security.Principal
import java.security.cert.X509Certificate

class ClosureX509PrincipalExtractorSpec extends AbstractIntegrationSpec {

    ClosureX509PrincipalExtractor x509PrincipalExtractor

    def setup() {
        x509PrincipalExtractor.closure = { return null }
    }

    def 'x509 principal extractor exception uses i18n message'() {
        given:
        def clientCert = Mock(X509Certificate) {
            getSubjectDN() >> Mock(Principal) {
                getName() >> 'non-existent@example.com'
            }
        }

        when:
        x509PrincipalExtractor.extractPrincipal(clientCert)

        then:
        def exception = thrown(BadCredentialsException)
        exception.message == 'Subject not found: non-existent@example.com'
    }
}
