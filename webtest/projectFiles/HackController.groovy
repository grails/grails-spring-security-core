import com.testapp.TestUser

class HackController {

	def getSessionValue = {
		def value = session[params.name]
		render value ? value.toString() : ''
	}

	def getSessionNames = {
		session.nowdate = new Date() // to test it's working

		def sb = new StringBuilder()
		session.attributeNames.each { String name ->
			sb.append name
			sb.append '<br/>\n'
		}
		render sb.toString()
	}

	def getPassword = {
		render TestUser.findByUsername(params.user).password
	}

	def clearAllData = {
		render 'ok'
	}
}
