import com.testapp.TestUser
import org.springframework.security.access.annotation.Secured

@Secured('permitAll')
class HackController {

	def userCache

	def getSessionValue(String name) {
		def value = session[name]
		render value ? value.toString() : ''
	}

	def getUserProperty(String user, String propName) {
		render TestUser.findByUsername(user)."$propName"
	}

	def setUserProperty() {
		def user = TestUser.findByUsername(params.user)
		user.properties = params
		user.save(flush: true)
		userCache.removeUserFromCache user.username
		render 'setUserProperty: OK'
	}
}
