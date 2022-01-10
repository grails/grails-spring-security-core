package demo

import grails.gorm.transactions.Transactional

class BootStrap {

    def init = { servletContext ->
        populate()
    }
    def destroy = {
    }

    @Transactional
    void populate() {
        Role roleAdmin = new Role(authority: 'ROLE_ADMIN')
        roleAdmin.save()
        Role roleDetective = new Role(authority: 'ROLE_DETECTIVE')
        roleDetective.save()
        User user = new User(username: 'sherlock', password: 'elementary')
        user.save()
        UserRole userRole = new UserRole(role: roleDetective, user: user)
        userRole.save()
    }
}
