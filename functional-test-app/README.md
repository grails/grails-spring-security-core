Functional tests
==================================

If you are testing changes in the plugin. You will need to:

-  Bump up the plugin version modifying `version.txt`
-  Install it in your maven local with `gradlew clean install`

To run functional tests invoke from the root of the repository: 

    ./copy_functional_tests_to_different_grails_versions.sh

    ./run_functional_tests.sh

### Copy Functional tests to different Grails Versions Script

This script `copy_functional_tests_to_different_grails_versions.sh` copies the functional tests code (domain classes, controllers, services, integration tests) to different Grails versions. 

Moreover, for those versions with Grails Wrapper, it invokes the `s2-quickstart` script to test domain class generation. 

`s2-quickstart` script generates different code depending on whether GORM version is larger than 6.1.1. Functional test validate that code generation. 

## Several Configurations

There are several configurations for functional tests: 

- static
- annotation
- requestmap
- basic
- misc
- bcrypt

With the use of System Properties you can run the functional tests with different browsers or configurations. 

E.g.

    $ ./gradlew clean install
    $ ./copy_functional_tests_to_different_grails_versions.sh
    $ cd functional-test-app/grails_3_2_8_gorm_6_1_1    
    $ ./gradlew -Dgeb.env=firefox -DTESTCONFIG=basic firefox 

#### How to add a new Grails versions to test against?

- Create a new grails app with the targeted version For example:     
    `functional-test-app $ sdk use grails 3.2.4`  
    `functional-test-app $ grails create-app grails_3_2_4`. 

- Remove grails artefacts which will be copied from the functional code. That it is to say, remove: 
`grails-app/controllers`, `grails-app/services`, `grails-app/domain`, `grails-app/i18n`, ‘grails-app/taglib’, ’grails-app/util’, ‘grails-app/tablig’, ‘grails-app/views’, `src`. 

Those files will be copied for you by the script. 

- Replace in `grails-app/conf/application.yml` the datasource configuration block with:

---
    hibernate:
       cache:
          queries: false
          use_query_cache: false
          use_second_level_cache: false
       format_sql: true
       use_sql_comments: true
    dataSource:
       dbCreate: update
       driverClassName: org.h2.Driver
       jmxExport: true
       password:
       pooled: true
      url:     jdbc:h2:mem:testDb;MVCC=TRUE;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE
      
- Add in `build.gradle` the next code at them bottom: 


    apply from: '../../gradle/ssc.gradle'
    apply from: '../../gradle/geb.gradle'
    apply from: '../../gradle/integrationTest.gradle'

    
- Add the new Grails version project folder name to `functional-test-app/build.gradle` and `./copy_functional_tests_to_different_grails_versions.sh`
and `./run_functional_tests.sh` scripts.
