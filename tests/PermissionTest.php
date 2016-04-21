<?php
use Lucid\Component\Permission\Permission;

class PermissionTest extends \PHPUnit_Framework_TestCase
{
    public $permission = null;

    public function setUp()
    {
        $fakeSession = [
            'user_id'=>5,
            'role_id'=>2,
        ];
        $this->permission = new Permission($fakeSession);
    }

    public function testLoggedIn()
    {
        $this->assertTrue($this->permission->isLoggedIn());
    }

    public function testGrantRevoke()
    {
        $this->assertEquals(count($this->permission->getPermissionsList()), 0);

        $this->assertFalse($this->permission->hasPermission('testPerm1'));
        $this->permission->grant('testPerm1');
        $this->assertTrue($this->permission->hasPermission('testPerm1'));
        $this->permission->revoke('testPerm1');
        $this->assertFalse($this->permission->hasPermission('testPerm1'));

        $this->assertEquals(count($this->permission->getPermissionsList()), 0);
        $this->permission->grant('testPerm1', 'testPerm2', 'testPerm3');
        $this->assertTrue($this->permission->hasPermission('testPerm2'));
        $this->assertTrue($this->permission->hasAnyPermission('testPerm2'));
        $this->permission->revoke('testPerm2');
        $this->assertTrue($this->permission->hasPermission('testPerm1'));
        $this->assertFalse($this->permission->hasPermission('testPerm2'));
        $this->assertFalse($this->permission->hasAnyPermission('testPerm2'));
        $this->assertTrue($this->permission->hasAnyPermission('testPerm1', 'testPerm2'));
        $this->permission->revoke('testPerm1', 'testPerm3');
        $this->assertEquals(count($this->permission->getPermissionsList()), 0);
    }
}