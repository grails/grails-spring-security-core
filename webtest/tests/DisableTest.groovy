import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder

class DisableTest extends AbstractSecurityWebTest {

	void testLockAccount() {

		// login as user1
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		// logout
		get '/logout'

		// lock account
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=accountLocked')
		get('/hack/setUserProperty?user=user1&accountLocked=true')
		assertEquals 'true', getContent('/hack/getUserProperty?user=user1&propName=accountLocked')

		// verify locked
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		assertContentContains 'accountLocked'

		// reset
		get('/hack/setUserProperty?user=user1&accountLocked=false')
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=accountLocked')
	}

	void testDisableAccount() {

		// login as user1
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		// logout
		get '/logout'

		// disable account
		assertEquals 'true', getContent('/hack/getUserProperty?user=user1&propName=enabled')
		get('/hack/setUserProperty?user=user1&enabled=false')
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=enabled')

		// verify disabled
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		assertContentContains 'accountDisabled'

		// reset
		get('/hack/setUserProperty?user=user1&enabled=true')
		assertEquals 'true', getContent('/hack/getUserProperty?user=user1&propName=enabled')
	}

	void testExpireAccount() {

		// login as user1
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		// logout
		get '/logout'

		// expire account
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=accountExpired')
		get('/hack/setUserProperty?user=user1&accountExpired=true')
		assertEquals 'true', getContent('/hack/getUserProperty?user=user1&propName=accountExpired')

		// verify expired
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		assertContentContains 'accountExpired'

		// reset
		get('/hack/setUserProperty?user=user1&accountExpired=false')
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=accountExpired')
	}

	void testExpirePassword() {

		// login as user1
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		// logout
		get '/logout'

		// expire password
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=passwordExpired')
		get('/hack/setUserProperty?user=user1&passwordExpired=true')
		assertEquals 'true', getContent('/hack/getUserProperty?user=user1&propName=passwordExpired')

		// verify expired
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		assertContentContains 'passwordExpired'

		// reset
		get('/hack/setUserProperty?user=user1&passwordExpired=false')
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=passwordExpired')
	}
}
