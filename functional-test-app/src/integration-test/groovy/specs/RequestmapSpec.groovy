package specs

import pages.requestmap.CreateRequestmapPage
import pages.requestmap.EditRequestmapPage
import pages.requestmap.ListRequestmapPage
import pages.requestmap.ShowRequestmapPage
import spock.lang.IgnoreIf

@IgnoreIf({ System.getProperty('TESTCONFIG') != 'requestmap' })
class RequestmapSpec extends AbstractSecuritySpec {

	void 'there are 20 initially'() {
		when:
		go 'testRequestmap/list?max=100'

		then:
		at ListRequestmapPage
		requestmapRows.size() == 20
	}

	void 'add a requestmap'() {
		when:
		to ListRequestmapPage
		newRequestmapButton.click()

		then:
		at CreateRequestmapPage

		when:
		$('form').url = '/nuevo/**'
		configAttribute = 'ROLE_ADMIN'
		createButton.click()

		then:
		at ShowRequestmapPage
		value('URL') == '/nuevo/**'
		configAttribute == 'ROLE_ADMIN'

		when:
		go 'testRequestmap/list?max=100'

		then:
		at ListRequestmapPage
		requestmapRows.size() == 21
	}

	void 'edit the details'() {
		when:
		go 'testRequestmap/list?max=100'

		then:
		at ListRequestmapPage

		when:
		requestmapRow(19).showLink.click()

		then:
		at ShowRequestmapPage

		when:
		editButton.click()

		then:
		at EditRequestmapPage

		when:
		$('form').url = '/secure2/**'
		configAttribute = 'ROLE_ADMINX'
		updateButton.click()

		then:
		at ShowRequestmapPage
		value('URL') == '/secure2/**'
		configAttribute == 'ROLE_ADMINX'
	}

	@IgnoreIf({ !System.getProperty('geb.env') || System.getProperty('geb.env') == 'htmlUnit' })
	void 'delete requestmap'() {
		when:
		go 'testRequestmap/list?max=100'

		then:
		at ListRequestmapPage

		when:
		requestmapRow(19).showLink.click()

		then:
		at ShowRequestmapPage

		when:
		def deletedId = id
		withConfirm { deleteButton.click() }

		then:
		at ListRequestmapPage
		message == "TestRequestmap $deletedId deleted"

		when:
		go 'testRequestmap/list?max=100'

		then:
		requestmapRows.size() == 20
	}
}
