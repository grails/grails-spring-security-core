import pages.IndexPage
import pages.LoginPage
import spock.lang.Stepwise

@Stepwise
class NamespaceSecuritySpec extends AbstractSecuritySpec {
	def setupSpec() {
		go 'testData/addTestUsers'
	}

	def setup() {
		browser.clearCookiesQuietly()
	}

	def 'should redirect to login page for anonymous'() {
		when:
			go uri

		then:
			at LoginPage

		where:
			uri << ['api/v1/books','api/v1/movies','api/v1/books.json','api/v1/movies.json']
	}


	def 'api not allowed for testuser'() {
		when:
			login 'testuser', 'password'

		then:
			at IndexPage

		when:
			go('api/v1/books' + format)

		then:
			$('.errors').text() == "Sorry, you're not authorized to view this page."

		when:
			go('api/v1/movies' + format)

		then:
			$('.errors').text() == "Sorry, you're not authorized to view this page."

		where:
			format << ['', '.json']
	}

	def 'verify security for testuser_books'() {
		when:
			login 'testuser_books', 'password'

		then:
			at IndexPage

		when:
			go('api/v1/books' + format)

		then:
			pageSource =~ /\{"class":"rest.Book","id":\d+,"title":"TestBook"\}/

		when:
			go('api/v1/movies' + format)

		then:
			$('.errors').text() == "Sorry, you're not authorized to view this page."
		where:
			format << ['', '.json']
	}

	def 'verify security for testuser_movies'() {
		when:
			login 'testuser_movies', 'password'

		then:
			at IndexPage

		when:
			go('api/v1/books' + format)

		then:
			$('.errors').text() == "Sorry, you're not authorized to view this page."

		when:
			go('api/v1/movies' + format)

		then:
			pageSource =~ /\{"class":"rest.Movie","id":\d+,"title":"TestMovie"\}/
		where:
			format << ['', '.json']
	}

	def 'verify security for testuser_books_and_movies'() {
		when:
			login 'testuser_books_and_movies', 'password'

		then:
			at IndexPage

		when:
			go('api/v1/books' + format)

		then:
			pageSource =~ /\{"class":"rest.Book","id":\d+,"title":"TestBook"\}/

		when:
			go('api/v1/movies' + format)

		then:
			pageSource =~ /\{"class":"rest.Movie","id":\d+,"title":"TestMovie"\}/
		where:
			format << ['', '.json']
	}

	def 'namespaced controller with same name can have different secured annotations - open'() {
		when:
			go 'openNamespaced'

		then:
			pageSource.contains 'open'
	}

	def 'namespaced controller with same name can have different secured annotations - secured'() {
		when:
			go 'secureNamespaced'

		then:
			at LoginPage
	}

}
