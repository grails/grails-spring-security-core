package demo

import grails.plugin.springsecurity.SpringSecurityService
import grails.plugin.springsecurity.annotation.Secured
import grails.gorm.transactions.Transactional
import groovy.transform.CompileStatic

@CompileStatic
@Secured('permitAll')
class SecuredController {

    SpringSecurityService springSecurityService

    @Secured('ROLE_ADMIN')
    def index() {
        render 'you have ROLE_ADMIN'
    }

    @Transactional
    def grantRoleHierarchyEntry() {
        def entry = 'ROLE_DETECTIVE > ROLE_ADMIN'
        new RoleHierarchyEntry(entry: entry).save(flush: 'true')
        springSecurityService.reloadDBRoleHierarchy()
        render 'OK'
    }
}