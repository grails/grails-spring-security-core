import org.springframework.security.access.annotation.Secured

@Secured(['ROLE_ADMIN'])
class FooBarController {
	def index() { render 'INDEX' }
	def barFoo() { render 'barFoo' }
}
