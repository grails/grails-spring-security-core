import pages.role.CreateRolePage
import pages.role.EditRolePage
import pages.role.ListRolePage
import pages.role.ShowRolePage
import spock.lang.Stepwise

@Stepwise
class RoleSpec extends AbstractSecuritySpec {

	def 'there are no roles initially'() {
		when:
			to ListRolePage

		then:
			roleRows.size() == 0
	}

	def 'add a role'() {
		when:
			to ListRolePage
			newRoleButton.click()

		then:
			at CreateRolePage

		when:
			authority = 'test'
			createButton.click()

		then:
			at ShowRolePage
			authority == 'test'
	}

	def 'edit the details'() {
		when:
			to ListRolePage
			roleRow(0).showLink.click()

		then:
			at ShowRolePage

		when:
			editButton.click()

		then:
			at EditRolePage

		when:
			authority = 'test_new'
			updateButton.click()

		then:
			at ShowRolePage

		when:
			to ListRolePage

		then:
			roleRows.size() == 1

			def row = roleRow(0)
			row.authority == 'test_new'
	}

	def 'show role'() {
		when:
			to ListRolePage
			roleRow(0).showLink.click()

		then:
			at ShowRolePage
	}

	def 'delete role'() {
		when:
			to ListRolePage
			roleRow(0).showLink.click()
			def deletedId = id

		then:
			at ShowRolePage

		when:
			withConfirm { deleteButton.click() }

		then:
			at ListRolePage

			message == "TestRole $deletedId deleted"
			roleRows.size() == 0
	}
}
