package specs

import pages.requestmap.CreateRequestmapPage
import pages.requestmap.EditRequestmapPage
import pages.requestmap.ListRequestmapPage
import pages.requestmap.ShowRequestmapPage

class RequestmapSpec extends AbstractSecuritySpec {

	void 'there are 26 initially'() {
		when:
		go 'testRequestmap/list?max=100'

		then:
		at ListRequestmapPage
		requestmapRows.size() == 26
	}

	void 'add a requestmap'() {
		when:
		to ListRequestmapPage
		newRequestmapButton.click()

		then:
		at CreateRequestmapPage

		when:
		$('form').url = '/secure/**'
		configAttribute = 'ROLE_ADMIN'
		createButton.click()

		then:
		at ShowRequestmapPage
		value('Url') == '/secure/**'
		configAttribute == 'ROLE_ADMIN'

		when:
		go 'testRequestmap/list?max=100'

		then:
		at ListRequestmapPage
		requestmapRows.size() == 27
	}

	void 'edit the details'() {
		when:
		go 'testRequestmap/list?max=100'

		then:
		at ListRequestmapPage

		when:
		requestmapRow(26).showLink.click()

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
		value('Url') == '/secure2/**'
		configAttribute == 'ROLE_ADMINX'
	}

	void 'delete requestmap'() {
		when:
		go 'testRequestmap/list?max=100'

		then:
		at ListRequestmapPage

		when:
		requestmapRow(26).showLink.click()

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
		requestmapRows.size() == 26
	}
}
