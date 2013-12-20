package test
/**
 * @author <a href='mailto:th3morg@gmail.com'>Ryan Morgan</a>
 */
class TestRoleGroupRoles implements Serializable{
    TestRoleGroup group
    TestRole role

    boolean equals(other) {
        if (!(other instanceof TestRoleGroupRoles)) {
            return false
        }

        other.role?.id == role?.id &&
                other.group?.id == group?.id
    }

    static TestRoleGroupRoles get(long roleId, long permissionId) {
        TestRoleGroupRoles.where {
            group == TestRoleGroup.load(roleId) &&
                    role == TestRole.load(permissionId)
        }.get()
    }

    static TestRoleGroupRoles create(TestRoleGroup role, TestRole permission, boolean flush = false) {
        new TestRoleGroupRoles(group: role, role: permission).save(flush: flush, insert: true)
    }

    static boolean remove(TestRoleGroup r, TestRole p) {
        int rowCount = TestRoleGroupRoles.where {
            group == TestRoleGroup.load(r.id) && role == TestRole.load(p.id)
        }.deleteAll()

        rowCount > 0
    }

    static void removeAllByPermission(TestRole p) {
        TestRoleGroupRoles.where {
            role == TestRole.load(p.id)
        }.deleteAll()
    }

    static void removeAllByRole(TestRoleGroup r) {
        TestRoleGroupRoles.where {
            group == TestRoleGroup.load(r.id)
        }.deleteAll()
    }

    static constraints = {
        role validator: {permission, obj ->
            if(get(obj.group.id, permission.id)){
                return "rolePermission.exists"
            }
        }
    }

    static mapping = {
        autoTimestamp true
        id composite: ['group', 'role']
    }
}
