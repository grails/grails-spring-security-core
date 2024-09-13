package com.testapp

import grails.plugin.springsecurity.SpringSecurityService
import org.grails.datastore.mapping.engine.event.AbstractPersistenceEvent
import org.grails.datastore.mapping.engine.event.PreInsertEvent
import org.grails.datastore.mapping.engine.event.PreUpdateEvent
import org.springframework.beans.factory.annotation.Autowired
import grails.events.annotation.gorm.Listener
import groovy.transform.CompileStatic
import jakarta.annotation.PostConstruct

@CompileStatic
class TestUserPasswordEncoderListener {

    String algorithm

    String reflectionSaltProperty

    @Autowired
    SpringSecurityService springSecurityService

    @PostConstruct
    void setup() {
        algorithm = springSecurityService.grailsApplication.config.get('grails.plugin.springsecurity.password.algorithm')
        reflectionSaltProperty = springSecurityService.grailsApplication.config.get('grails.plugin.springsecurity.dao.reflectionSaltSourceProperty')
    }

    @Listener(TestUser)
    void onPreInsertEvent(PreInsertEvent event) {
        encodeUserPasswordForEvent(event)
    }

    @Listener(TestUser)
    void onPreUpdateEvent(PreUpdateEvent event) {
        encodeUserPasswordForEvent(event)
    }

    private void encodeUserPasswordForEvent(AbstractPersistenceEvent event) {
        if (event.entityObject instanceof TestUser) {
            TestUser u = (event.entityObject as TestUser)
            if (u.password && ((event instanceof  PreInsertEvent) || (event instanceof PreUpdateEvent && u.isDirty('password')))) {
                event.getEntityAccess().setProperty("password", encodePassword(u))
            }
        }
    }

    private String encodePassword(TestUser u) {
        springSecurityService?.passwordEncoder ? springSecurityService.encodePassword(u.password) : u.password
    }

    private def salt(TestUser u) {
        if ( !springSecurityService ) {
            return null
        }

        if ( algorithm == 'bcrypt' || algorithm == 'pbkdf2' ) {
            return null
        }
        if ( reflectionSaltProperty ) {
            return u.getProperty(reflectionSaltProperty)
        }
        null
    }
}