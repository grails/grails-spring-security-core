package pages

import geb.Page

class LoginPage extends Page {

	static url = 'login/auth'

	static at = { title == 'Login' }

	static content = {
		loginForm { $('form') }
		username { $('input', type: 'text',     name: 'j_username') }
		password { $('input', type: 'password', name: 'j_password') }
		rememberMe { $('input', type: 'checkbox', name: '_spring_security_remember_me') }
//		$('#remember_me')
		loginButton { $('input', type: 'submit', value: 'Login') }
	}
}
