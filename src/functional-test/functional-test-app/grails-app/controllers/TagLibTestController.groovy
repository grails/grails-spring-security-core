import org.springframework.security.access.annotation.Secured

@Secured('permitAll')
class TagLibTestController {

	def test() {}

	def testMetaclassMethods() {

		render """
		getPrincipal: ${getPrincipal()}<br/>
		principal: $principal<br/>

		isLoggedIn: ${isLoggedIn()}<br/>
		loggedIn: $loggedIn<br/>

		getAuthenticatedUser: ${getAuthenticatedUser()}<br/>
		authenticatedUser: $authenticatedUser<br/>
		"""
	}
}
