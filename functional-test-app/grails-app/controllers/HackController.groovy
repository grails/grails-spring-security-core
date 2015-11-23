import grails.util.Metadata

import org.springframework.security.access.annotation.Secured

import com.testapp.TestUser

@Secured('permitAll')
class HackController {

	def userCache

	def getSessionValue(String name) {
		def value = session[name]
		render value ? value.toString() : ''
	}

	def getSessionNames() {
		session.nowdate = new Date() // to test it's working

		def sb = new StringBuilder()
		session.attributeNames.each { sb << it << '<br/>\n' }
		render sb.toString()
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

	def clearAllData() {
		render 'clearAllData: OK'
	}

	def grailsVersion() {
		render Metadata.current.getGrailsVersion()
	}
}
