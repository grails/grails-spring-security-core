import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder

class BCryptTest extends AbstractSecurityWebTest {

	void testBCrypt() {
		createUser()

		String encryptedPassword = getContent(
			'/hack/getUserProperty?user=user1&propName=password', true)

		assertTrue encryptedPassword.startsWith('$2a$')

		def shaPasswordEncoder = new MessageDigestPasswordEncoder('SHA-256')
		String notSalted = shaPasswordEncoder.encodePassword('p4ssw0rd', null)
		String salted = shaPasswordEncoder.encodePassword('p4ssw0rd', 'user1')

		assertFalse salted == encryptedPassword
		assertFalse notSalted == encryptedPassword
	}

	private void createUser() {
		get '/testUser'
		click 'New TestUser'
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
