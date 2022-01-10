package spring

import com.test.AdditionalLogoutHandler
import grails.plugin.springsecurity.web.authentication.preauth.x509.ClosureX509PrincipalExtractor

beans = {
	additionalLogoutHandler(AdditionalLogoutHandler)

	x509PrincipalExtractor(ClosureX509PrincipalExtractor)
}
