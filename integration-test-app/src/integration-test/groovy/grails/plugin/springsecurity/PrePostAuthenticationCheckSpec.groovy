package grails.plugin.springsecurity


import org.springframework.security.authentication.AccountExpiredException
import org.springframework.security.authentication.CredentialsExpiredException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.LockedException
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsChecker
import spock.lang.Unroll

class PrePostAuthenticationCheckSpec extends AbstractIntegrationSpec {

    UserDetailsChecker preAuthenticationChecks
    UserDetailsChecker postAuthenticationChecks

    @Unroll
    def 'pre-authentication exception uses i18n message - #test'() {
        given:
        def userDetails = Mock(UserDetails) {
            isAccountNonLocked() >> { test != 'locked' }
            isEnabled() >> { test != 'disabled' }
            isAccountNonExpired() >> { test != 'expired'}
        }

        when:
        preAuthenticationChecks.check(userDetails)

        then:
        Exception exception = thrown(type)
        exception.message == expectMessage

        where:
        test       | type                    | expectMessage
        'locked'   | LockedException         | 'Custom user account is locked.'
        'disabled' | DisabledException       | 'Custom user account is disabled.'
        'expired'  | AccountExpiredException | 'Custom user account is expired.'
    }

    def 'post-authentication exception uses i18n message - credentials expired'() {
        given:
        def userDetails = Mock(UserDetails) {
            isCredentialsNonExpired() >> false
        }

        when:
        postAuthenticationChecks.check(userDetails)

        then:
        Exception exception = thrown(CredentialsExpiredException)
        exception.message == 'Custom user credentials are expired.'
    }
}
