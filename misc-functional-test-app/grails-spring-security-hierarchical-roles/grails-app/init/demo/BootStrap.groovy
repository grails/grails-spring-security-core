package demo

class BootStrap {

    def init = { servletContext ->

        final boolean flush = true
        final boolean failOnError = true
        def roleAdmin = new Role(authority: 'ROLE_ADMIN')
        roleAdmin.save(flush: flush, failOnError: true)

        def roleDetective = new Role(authority: 'ROLE_DETECTIVE')
        roleDetective.save(flush: flush, failOnError: true)

        def user = new User(username: 'sherlock', password: 'elementary')
        user.save(flush: flush)
        def userRole = new UserRole(role: roleDetective, user: user)
        userRole.save(flush: flush, failOnError: failOnError)


    }
    def destroy = {
    }
}
