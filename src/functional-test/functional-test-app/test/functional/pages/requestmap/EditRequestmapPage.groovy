package pages.requestmap

import pages.EditPage

class EditRequestmapPage extends EditPage {
	static content = {
		updateButton(to: ShowRequestmapPage) { $('input', value: 'Update') }
		deleteButton(to: ListRequestmapPage) { $('input', value: 'Delete') }
	}
}
