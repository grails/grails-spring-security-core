package namespaced.secure

import grails.plugin.springsecurity.annotation.Secured

@Secured('IS_AUTHENTICATED_FULLY')
class NamespacedController {

    static namespace = "secure"

    def index() {
        render 'secure'
    }
}
