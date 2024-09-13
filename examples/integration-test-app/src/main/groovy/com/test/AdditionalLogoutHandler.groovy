package com.test

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.logout.LogoutHandler

class AdditionalLogoutHandler implements LogoutHandler {

	boolean called

	void logout(HttpServletRequest req, HttpServletResponse res, Authentication a) {
		called = true
	}
}
