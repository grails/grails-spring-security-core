package specs

import pages.IndexPage
import pages.LoginPage

class NamespaceSecuritySpec extends AbstractSecuritySpec {

	protected void resetDatabase() {
		super.resetDatabase()
		go 'testData/addTestUsers'
	}

	void 'should redirect to login page for anonymous'() {
		when:
		go 'api/v1/' + uri

		then:
		at LoginPage

		where:
		uri << ['books', 'books.json', 'movies', 'movies.json']
	}

	void 'api not allowed for testuser'() {
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

	void 'verify security for testuser_books'() {
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

	void 'verify security for testuser_movies'() {
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

	void 'verify security for testuser_books_and_movies'() {
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

	void 'namespaced controller with same name can have different secured annotations - open'() {
		when:
		go 'openNamespaced'

		then:
		pageSource.contains 'open'
	}

	void 'namespaced controller with same name can have different secured annotations - secured'() {
		when:
		go 'secureNamespaced'

		then:
		at LoginPage
	}
}
