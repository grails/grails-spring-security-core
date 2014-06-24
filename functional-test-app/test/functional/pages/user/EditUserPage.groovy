package pages.user

import pages.EditPage

class EditUserPage extends EditPage {
	static content = {
		updateButton(to: ShowUserPage) { $('input', value: 'Update') }
		deleteButton(to: ListUserPage) { $('input', value: 'Delete') }
	}
}
