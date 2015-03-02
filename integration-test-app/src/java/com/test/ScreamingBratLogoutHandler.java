package com.test;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ScreamingBratLogoutHandler implements LogoutHandler {

    @Override
    public void logout(HttpServletRequest servletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
    }

}
