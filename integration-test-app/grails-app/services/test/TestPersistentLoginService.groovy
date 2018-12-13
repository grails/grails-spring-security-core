package test

import grails.gorm.services.Service
import grails.gorm.transactions.ReadOnly

interface ITestPersistentLoginService {

    List<TestPersistentLogin> findAll(Map args)

    TestPersistentLogin save(String series, String token, String username, Date lastUsed)

    Number countByUsername(String username)
}

@Service(TestPersistentLogin)
abstract class TestPersistentLoginService implements ITestPersistentLoginService {

    @ReadOnly
    TestPersistentLogin get(String series) {
        TestPersistentLogin.get(series)
    }
}