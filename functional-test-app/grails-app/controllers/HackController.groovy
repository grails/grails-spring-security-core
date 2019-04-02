import com.testapp.HackService
import org.springframework.security.access.annotation.Secured


@Secured('permitAll')
class HackController {

	def userCache
	HackService hackService

	def getSessionValue(String name) {
		def value = session[name]
		render value ? value.toString() : ''
	}

	def getUserProperty(String user, String propName) {
		String result = "false"
		if (propName && user) {
			result = hackService.findByUsername(user)?.getProperty(propName)
			if (!result) {
				result = "false"
			}
		} else {
			result = "false"
		}
		render(result)
	}

	def setUserProperty() {
		def user = hackService.updateUser(params.user,params)
		userCache.removeUserFromCache user.username
		render 'setUserProperty: OK'
	}

	def blankPage() {
		render ''
	}
}
