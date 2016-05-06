import test.Role
import test.User
import test.UserRole

class BootStrap {

	def init = {
		def admin = new User(username: 'admin', password: 'password').save(failOnError: true)
		def roleAdmin = new Role(authority: 'ROLE_ADMIN').save(failOnError: true)
		UserRole.create admin, roleAdmin

		def roleUser = new Role(authority: 'ROLE_USER').save(failOnError: true)
		def user = new User(username: 'user', password: 'password').save(failOnError: true)
		UserRole.create user, roleUser

		User.withSession {
			it.flush()
			it.clear()
		}

		assert Role.count() == 2
		assert User.count() == 2
		assert UserRole.count() == 2
	}
}
