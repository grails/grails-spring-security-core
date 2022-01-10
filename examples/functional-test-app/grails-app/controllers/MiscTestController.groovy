import org.springframework.security.access.annotation.Secured

@Secured('permitAll')
class MiscTestController {

	def test() {}

	def testControllerMethods() {
		render """
		getPrincipal: ${getPrincipal()}<br/>
		principal: $principal<br/>

		isLoggedIn: ${isLoggedIn()}<br/>
		loggedIn: $loggedIn<br/>

		getAuthenticatedUser: ${getAuthenticatedUser()}<br/>
		authenticatedUser: $authenticatedUser<br/>
		"""
	}

	def testServletApiMethods() {
		render """
		request.getUserPrincipal(): ${request.getUserPrincipal()}<br/>
		request.userPrincipal: $request.userPrincipal<br/>

		request.isUserInRole('ROLE_ADMIN'): ${request.isUserInRole('ROLE_ADMIN')}<br/>
		request.isUserInRole('ROLE_FOO'): ${request.isUserInRole('ROLE_FOO')}<br/>

		request.getRemoteUser(): ${request.getRemoteUser()}<br/>
		request.remoteUser: $request.remoteUser<br/>
		"""
	}
}
