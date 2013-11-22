import pages.user.CreateUserPage
import pages.user.EditUserPage
import pages.user.ListUserPage
import pages.user.ShowUserPage
import spock.lang.Stepwise

@Stepwise
class UserSpec extends AbstractSecuritySpec {

	def 'there are no users initially'() {
		when:
			to ListUserPage

		then:
			userRows.size() == 0
	}

	def 'add a user'() {
		when:
			to ListUserPage
			newUserButton.click()

		then:
			at CreateUserPage

		when:
			username = 'new_user'
			password = 'p4ssw0rd'
			$('#enabled').click()
			createButton.click()

		then:
			at ShowUserPage
			username == 'new_user'
			enabled == true
	}

	def 'edit the details'() {
		when:
			to ListUserPage
			userRow(0).showLink.click()

		then:
			at ShowUserPage

		when:
			editButton.click()

		then:
			at EditUserPage

		when:
			username = 'new_user2'
			password = 'p4ssw0rd2'
			$('#enabled').click()

			updateButton.click()

		then:
			at ShowUserPage

		when:
			to ListUserPage

		then:
			userRows.size() == 1

			def row = userRow(0)
			row.username == 'new_user2'
			!row.enabled
	}

	def 'show user'() {
		when:
			to ListUserPage
			userRow(0).showLink.click()

		then:
			at ShowUserPage
	}

	def 'delete user'() {
		when:
			to ListUserPage
			userRow(0).showLink.click()
			def deletedId = id

		then:
			at ShowUserPage

		when:
			withConfirm { deleteButton.click() }

		then:
			at ListUserPage

			message == "TestUser $deletedId deleted."
			userRows.size() == 0
	}
}
