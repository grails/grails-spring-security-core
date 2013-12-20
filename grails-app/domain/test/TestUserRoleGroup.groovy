package test

/**
 * @author <a href='mailto:th3morg@gmail.com'>Ryan Morgan</a>
 */
class TestUserRoleGroup implements Serializable{
    TestUser user
    TestRoleGroup group

    boolean equals(other) {
        if (!(other instanceof TestUserRoleGroup)) {
            return false
        }

        other.user?.id == user?.id &&
                other.group?.id == group?.id
    }

    static TestUserRoleGroup get(long userId, long roleId) {
        TestUserRoleGroup.where {
            user == TestUser.load(userId) &&
                    group == TestRoleGroup.load(roleId)
        }.get()
    }

    static TestUserRoleGroup create(TestUser user, TestRoleGroup role, boolean flush = false) {
        new TestUserRoleGroup(user: user, group: role).save(flush: flush, insert: true)
    }

    static boolean remove(TestUser u, TestRoleGroup r) {

        int rowCount = TestUserRoleGroup.where {
            user == TestUser.load(u.id) &&
                    group == TestRoleGroup.load(r.id)
        }.deleteAll()

        rowCount > 0
    }

    static void removeAll(TestUser u) {
        TestUserRoleGroup.where {
            user == TestUser.load(u.id)
        }.deleteAll()
    }

    static void removeAll(TestRoleGroup r) {
        TestUserRoleGroup.where {
            group == TestRoleGroup.load(r.id)
        }.deleteAll()
    }

    static mapping = {
        id composite: ['group', 'user']
    }

}
