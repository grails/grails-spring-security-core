package functional.test.app

import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.SpringSecurityUtils

class BootStrap {
    def init = { servletContext ->
        String testconfig = System.getProperty('TESTCONFIG')
        switch (testconfig) {
            case 'issue503':
                SpringSecurityUtils.clientRegisterFilter 'maintenanceModeFilter', SecurityFilterPosition.FILTER_SECURITY_INTERCEPTOR.order + 10
                break
        }
    }
}
