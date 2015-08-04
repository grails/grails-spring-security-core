import pages.IndexPage
import pages.role.CreateRolePage
import pages.role.ListRolePage
import pages.role.ShowRolePage
import pages.user.CreateUserPage
import pages.user.ListUserPage
import pages.user.ShowUserPage
import spock.lang.Stepwise

@Stepwise
class MiscSpec extends AbstractSecuritySpec {

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
			username = 'user1'
			password = 'p4ssw0rd'
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
			username = 'user2'
			password = 'p4ssw0rd2'
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

	def 'salted password'() {

		when:
			String encryptedPassword = getContent('hack/getUserProperty?user=user1&propName=password')
			def passwordEncoder = createSha256Encoder()
			String notSalted = passwordEncoder.encodePassword('p4ssw0rd', null)
			String salted = passwordEncoder.encodePassword('p4ssw0rd', 'user1')

		then:
			salted == encryptedPassword
			notSalted != encryptedPassword
	}

	def 'switch user'() {

		when:
			login 'user1', 'p4ssw0rd'

		then:
			at IndexPage

		// verify logged in
		when:
			go 'secure-annotated'

		then:
			assertContentContains 'you have ROLE_ADMIN'

		when:
			String auth = getSessionValue('SPRING_SECURITY_CONTEXT')

		then:
			auth.contains 'Username: user1'
			auth.contains 'Authenticated: true'
			auth.contains 'ROLE_ADMIN'
			auth.contains 'ROLE_USER' // new, added since inferred from role hierarchy
			!auth.contains('ROLE_PREVIOUS_ADMINISTRATOR')

		// switch
		when:
			go 'j_spring_security_switch_user?j_username=user2'

		then:
			assertContentContains 'Welcome to Grails'

		// verify logged in as user1

		when:
			auth = getSessionValue('SPRING_SECURITY_CONTEXT')

		then:
			auth.contains 'Username: user2'
			auth.contains 'Authenticated: true'
			auth.contains 'ROLE_USER'
			auth.contains 'ROLE_PREVIOUS_ADMINISTRATOR'

		when:
			go 'secure-annotated/user-action'

		then:
			assertContentContains 'you have ROLE_USER'

		// verify not logged in as admin
		when:
			go 'secure-annotated/admin-either'

		then:
			assertContentContains "Sorry, you're not authorized to view this page."

		// switch back
		when:
			go 'j_spring_security_exit_user'

		then:
			assertContentContains 'Welcome to Grails'

		// verify logged in as admin
		when:
			go 'secure-annotated/admin-either'

		then:
			assertContentContains 'you have ROLE_ADMIN'

		when:
			auth = getSessionValue('SPRING_SECURITY_CONTEXT')

		then:
			auth.contains 'Username: user1'
			auth.contains 'Authenticated: true'
			auth.contains 'ROLE_ADMIN'
			auth.contains 'ROLE_USER'
			!auth.contains('ROLE_PREVIOUS_ADMINISTRATOR')
	}

	def 'hierarchical roles'() {

		when:
			login 'user1', 'p4ssw0rd'

		then:
			at IndexPage

		// verify logged in
		when:
			go 'secure-annotated'

		then:
			assertContentContains 'you have ROLE_ADMIN'

		when:
			String auth = getSessionValue('SPRING_SECURITY_CONTEXT')

		then:
			auth.contains 'Authenticated: true'
			auth.contains 'ROLE_USER'

		// now get an action that's ROLE_USER only
		when:
			go 'secure-annotated/user-action'

		then:
			assertContentContains 'you have ROLE_USER'
	}

	def 'taglibs unauthenticated'() {

		when:
			go 'tag-lib-test/test'

		then:
			assertContentDoesNotContain 'user and admin'
			assertContentDoesNotContain 'user and admin and foo'
			assertContentContains 'not user and not admin'
			assertContentDoesNotContain 'user or admin'
			assertContentContains 'accountNonExpired: "not logged in"'
			assertContentContains 'id: "not logged in"'
			assertContentContains 'Username is ""'
			assertContentDoesNotContain 'logged in true'
			assertContentContains 'logged in false'
			assertContentDoesNotContain 'switched true'
			assertContentContains 'switched false'
			assertContentContains 'switched original username ""'
			assertContentDoesNotContain 'access with role user: true'
			assertContentDoesNotContain 'access with role admin: true'
			assertContentContains 'access with role user: false'
			assertContentContains 'access with role admin: false'
	}

	def 'taglibs user'() {

		when:
			login 'user2', 'p4ssw0rd2'

		then:
			at IndexPage

		when:
			go 'tag-lib-test/test'

		then:
			assertContentDoesNotContain 'user and admin'
			assertContentDoesNotContain 'user and admin and foo'
			assertContentDoesNotContain 'not user and not admin'
			assertContentContains 'user or admin'
			assertContentContains 'accountNonExpired: "true"'
			assertContentDoesNotContain 'id: "not logged in"' // can't test on exact id, don't know what it is
			assertContentContains 'Username is "user2"'
			assertContentContains 'logged in true'
			assertContentDoesNotContain 'logged in false'
			assertContentDoesNotContain 'switched true'
			assertContentContains 'switched false'
			assertContentContains 'switched original username ""'

			assertContentContains 'access with role user: true'
			assertContentDoesNotContain 'access with role admin: true'
			assertContentDoesNotContain 'access with role user: false'
			assertContentContains 'access with role admin: false'

			assertContentContains 'Can access /login/auth'
			assertContentDoesNotContain 'Can access /secureAnnotated'
			assertContentDoesNotContain 'Cannot access /login/auth'
			assertContentContains 'Cannot access /secureAnnotated'
	}

	def 'taglibs admin'() {

		when:
			login 'user1', 'p4ssw0rd'

		then:
			at IndexPage

		when:
			go 'tag-lib-test/test'

		then:
			assertContentContains 'user and admin'
			assertContentDoesNotContain 'user and admin and foo'
			assertContentDoesNotContain 'not user and not admin'
			assertContentContains 'user or admin'
			assertContentContains 'accountNonExpired: "true"'
			assertContentDoesNotContain 'id: "not logged in"' // can't test on exact id, don't know what it is
			assertContentContains 'Username is "user1"'

			assertContentContains 'logged in true'
			assertContentDoesNotContain 'logged in false'
			assertContentDoesNotContain 'switched true'
			assertContentContains 'switched false'
			assertContentContains 'switched original username ""'

			assertContentContains 'access with role user: true'
			assertContentContains 'access with role admin: true'
			assertContentDoesNotContain 'access with role user: false'
			assertContentDoesNotContain 'access with role admin: false'

			assertContentContains 'Can access /login/auth'
			assertContentContains 'Can access /secureAnnotated'
			assertContentDoesNotContain 'Cannot access /login/auth'
			assertContentDoesNotContain 'Cannot access /secureAnnotated'
	}

	def 'metaclass methods unauthenticated'() {

		when:
			go 'tag-lib-test/testMetaclassMethods'

		then:
			assertContentContains 'getPrincipal: org.springframework.security.core.userdetails.User'
			assertContentContains 'Username: __grails.anonymous.user__'
			assertContentContains 'Granted Authorities: ROLE_ANONYMOUS'
			assertContentContains 'isLoggedIn: false'
			assertContentContains 'loggedIn: false'
			assertContentContains 'getAuthenticatedUser: null'
			assertContentContains 'authenticatedUser: null'
	}

	def 'metaclass methods authenticated'() {

		when:
			login 'user1', 'p4ssw0rd'

		then:
			at IndexPage

		when:
			go 'tag-lib-test/testMetaclassMethods'

		then:
			assertContentContains 'getPrincipal: grails.plugin.springsecurity.userdetails.GrailsUser'
			assertContentContains 'principal: grails.plugin.springsecurity.userdetails.GrailsUser'
			assertContentContains 'Username: user1'
			assertContentContains 'isLoggedIn: true'
			assertContentContains 'loggedIn: true'
			assertContentContains 'getAuthenticatedUser: user1'
			assertContentContains 'authenticatedUser: user1'
	}

	def 'test hyphenated'() {

		when:
			go 'foo-bar'

		then:
			assertContentContains 'Please Login'

		when:
			go 'foo-bar/index'

		then:
			assertContentContains 'Please Login'

		when:
			go 'foo-bar/bar-foo'

		then:
			assertContentContains 'Please Login'

		when:
			logout()
			login 'user1', 'p4ssw0rd'

		then:
			at IndexPage

		when:
			go 'foo-bar'

		then:
			assertContentContains 'INDEX'

		when:
			go 'foo-bar/index'

		then:
			assertContentContains 'INDEX'

		when:
			go 'foo-bar/bar-foo'

		then:
			assertContentContains 'barFoo'
	}
}
