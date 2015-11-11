import test.Role
import test.User
import test.UserRole

class BootStrap {

	def init = {
		def admin = new User('admin', 'password').save(failOnError: true)
		def roleAdmin = new Role('ROLE_ADMIN').save(failOnError: true)
		UserRole.create admin, roleAdmin

		def roleUser = new Role('ROLE_USER').save(failOnError: true)
		def user = new User('user', 'password').save(failOnError: true)
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
