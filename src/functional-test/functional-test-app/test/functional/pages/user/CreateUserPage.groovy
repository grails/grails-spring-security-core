package pages.user

import pages.CreatePage

class CreateUserPage extends CreatePage {
	static content = {
		createButton(to: ShowUserPage) { create() }
	}
}
