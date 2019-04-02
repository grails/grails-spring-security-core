package com.testapp

import grails.gorm.services.Service

@Service(TestUser)
abstract class HackService {

    abstract TestUser save(TestUser testUser)

    abstract TestUser findByUsername(String username)

    abstract TestUser update(Serializable id, Boolean accountLocked)

    TestUser updateUser(String username, Map params) {
        TestUser user = TestUser.findByUsername username
        user.properties = params
        save(user)
    }

}
