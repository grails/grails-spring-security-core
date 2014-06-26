import pages.IndexPage
import pages.LoginPage
import pages.requestmap.CreateRequestmapPage
import pages.requestmap.ListRequestmapPage
import pages.requestmap.ShowRequestmapPage
import pages.role.CreateRolePage
import pages.role.ListRolePage
import pages.role.ShowRolePage
import pages.user.CreateUserPage
import pages.user.ListUserPage
import pages.user.ShowUserPage
import spock.lang.Stepwise

@Stepwise
class RequestmapSecuritySpec extends AbstractSecuritySpec {

	def 'create roles'() {
		when:
			to ListRolePage

		then:
			roleRows.size() == 0

		when:
			newRoleButton.click()

		then:
			at CreateRolePage

		when:
			authority = 'ROLE_ADMIN'
			createButton.click()

		then:
			at ShowRolePage

		when:
			to ListRolePage

		then:
			roleRows.size() == 1

		when:
			newRoleButton.click()

		then:
			at CreateRolePage

		when:
			authority = 'ROLE_USER'
			createButton.click()

		then:
			at ShowRolePage

		when:
			to ListRolePage

		then:
			roleRows.size() == 2
	}

	def 'create users'() {
		when:
			to ListUserPage

   	then:
   		userRows.size() == 0

   	when:
   		newUserButton.click()

   	then:
   		at CreateUserPage

   	when:
   		username = 'admin1'
   		password = 'password1'
   		$('#enabled').click()
			$('#ROLE_ADMIN').click()
			createButton.click()

   	then:
   		at ShowUserPage

   	when:
   		to ListUserPage

   	then:
   		userRows.size() == 1

   	when:
   		newUserButton.click()

   	then:
   		at CreateUserPage

   	when:
			username = 'user1'
			password = 'p4ssw0rd'
   		$('#enabled').click()
			$('#ROLE_USER').click()
   		createButton.click()

   	then:
   		at ShowUserPage

   	when:
   		to ListUserPage

   	then:
   		userRows.size() == 2
	}

	def 'secure page not visible without requestmap'() {
		when:
			go 'secure'

		then:
			assertContentContains 'was denied as public invocations are not allowed via this interceptor'

		when:
			go 'secure/expression'

		then:
			assertContentContains 'was denied as public invocations are not allowed via this interceptor'
	}

	def 'create requestMaps'() {

		when:
			go 'testRequestmap/list?max=100'

   	then:
   		at ListRequestmapPage
   		def initialSize = requestmapRows.size() // initial 22 from BootStrap
		initialSize in [25,26]

		when:
			newRequestmapButton.click()

		then:
			at CreateRequestmapPage

   	when:
			$('form').url = '/secure'
			configAttribute = 'ROLE_ADMIN'
			createButton.click()

   	then:
   		at ShowRequestmapPage

		when:
			go 'testRequestmap/list?max=100'

   	then:
   		at ListRequestmapPage
   		requestmapRows.size() == initialSize + 1

		when:
			newRequestmapButton.click()

		then:
			at CreateRequestmapPage

		when:
			$('form').url = '/secure/**'
			configAttribute = 'ROLE_ADMIN'
			createButton.click()

		then:
			at ShowRequestmapPage

		when:
			go 'testRequestmap/list?max=100'

		then:
			at ListRequestmapPage
			requestmapRows.size() == initialSize + 2

		when:
			newRequestmapButton.click()

		then:
			at CreateRequestmapPage

		when:
			$('form').url = '/secure/expression'
			configAttribute = "authentication.name == 'user1'"
			createButton.click()

		then:
			at ShowRequestmapPage

		when:
			go 'testRequestmap/list?max=100'

		then:
			at ListRequestmapPage
			requestmapRows.size() == initialSize + 3
	}

	def 'secured urls not visible without login'() {

		when:
			go 'secure'

		then:
			at LoginPage

		when:
			go 'secure/expression'

		then:
			at LoginPage

		when:
			go 'secure/index.xml'

		then:
			at LoginPage

		when:
			go 'secure/index;jsessionid=5514B068198CC7DBF372713326E14C12'

		then:
			at LoginPage
	}

	def 'check allowed for admin1'() {

		when:
			login 'admin1', 'password1'

		then:
			at IndexPage

		// Check that with a requestmap, /secure is accessible after login
		when:
			go 'secure'

		then:
			assertContentContains 'SECURE'

			// but 'expression' requires user1
		when:
			go 'secure/expression'

		then:
			assertContentContains "Sorry, you're not authorized to view this page."
	}

	def 'check allowed for user1'() {

		when:
			login 'user1', 'p4ssw0rd'

		then:
			at IndexPage

		// Check that with a requestmap, /secure is accessible after login
		when:
			go 'secure'

		then:
			assertContentContains "Sorry, you're not authorized to view this page."

		when:
			go 'secure/expression'

		then:
			assertContentContains 'OK'
	}
}
