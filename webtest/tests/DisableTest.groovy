class DisableTest extends AbstractSecurityWebTest {

	void testAll() {
		_testLockAccount()
		tearDown()

		_testDisableAccount()
		tearDown()

		_testExpireAccount()
		tearDown()

		_testExpirePassword()
	}

	void _testLockAccount() {

		login 'user1', 'p4ssw0rd'

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		logout()

		// lock account
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=accountLocked')
		get('/hack/setUserProperty?user=user1&accountLocked=true')
		assertEquals 'true', getContent('/hack/getUserProperty?user=user1&propName=accountLocked')

		// verify locked
		login 'user1', 'p4ssw0rd'

		assertContentContains 'accountLocked'

		// reset
		get('/hack/setUserProperty?user=user1&accountLocked=false')
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=accountLocked')
	}

	void _testDisableAccount() {

		login 'user1', 'p4ssw0rd'

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		logout()

		// disable account
		assertEquals 'true', getContent('/hack/getUserProperty?user=user1&propName=enabled')
		get('/hack/setUserProperty?user=user1&enabled=false')
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=enabled')

		// verify disabled
		login 'user1', 'p4ssw0rd'

		assertContentContains 'accountDisabled'

		// reset
		get('/hack/setUserProperty?user=user1&enabled=true')
		assertEquals 'true', getContent('/hack/getUserProperty?user=user1&propName=enabled')
	}

	void _testExpireAccount() {

		login 'user1', 'p4ssw0rd'

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		logout()

		// expire account
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=accountExpired')
		get('/hack/setUserProperty?user=user1&accountExpired=true')
		assertEquals 'true', getContent('/hack/getUserProperty?user=user1&propName=accountExpired')

		// verify expired
		login 'user1', 'p4ssw0rd'

		assertContentContains 'accountExpired'

		// reset
		get('/hack/setUserProperty?user=user1&accountExpired=false')
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=accountExpired')
	}

	void _testExpirePassword() {

		login 'user1', 'p4ssw0rd'

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		logout()

		// expire password
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=passwordExpired')
		get('/hack/setUserProperty?user=user1&passwordExpired=true')
		assertEquals 'true', getContent('/hack/getUserProperty?user=user1&propName=passwordExpired')

		// verify expired
		login 'user1', 'p4ssw0rd'

		assertContentContains 'passwordExpired'

		// reset
		get('/hack/setUserProperty?user=user1&passwordExpired=false')
		assertEquals 'false', getContent('/hack/getUserProperty?user=user1&propName=passwordExpired')
	}
}
