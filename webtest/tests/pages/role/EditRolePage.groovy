package pages.role

import pages.EditPage

class EditRolePage extends EditPage {
	static content = {
		updateButton(to: ShowRolePage) { $('input', value: 'Update') }
		deleteButton(to: ListRolePage) { $('input', value: 'Delete') }
	}
}
