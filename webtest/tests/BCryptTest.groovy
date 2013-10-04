class BCryptTest extends AbstractSecurityWebTest {

	void testBCrypt() {
		createUser()

		String encryptedPassword = getContent('/hack/getUserProperty?user=user1&propName=password', true)

		assertTrue encryptedPassword.startsWith('$2a$')

		def shaPasswordEncoder = createSha256Encoder()
		String notSalted = shaPasswordEncoder.encodePassword('p4ssw0rd', null)
		String salted = shaPasswordEncoder.encodePassword('p4ssw0rd', 'user1')

		assertFalse salted == encryptedPassword
		assertFalse notSalted == encryptedPassword
	}

	private void createUser() {
		get '/testUser/create'
		form {
			username = 'user1'
			password = 'p4ssw0rd'
			enabled = true
		}
		clickButton 'Create'

		click 'TestUser List'
		verifyListSize 1
	}
}
