<?php
namespace Lucid\Component\Permission;

class Permission implements PermissionInterface
{
    public $idField = 'user_id';
    protected $session;

    public function __construct($session = null)
    {
        if (is_null($session) === true) {
            $this->session = new \Lucid\Component\Container\SessionContainer();
        } else {
            if (is_array($session) === true) {
                $this->session = new \Lucid\Component\Container\Container();
                $this->session->setSource($session);
            } else {
                if (is_object($session) === false || in_array('Lucid\Component\Container\ContainerInterface', class_implements($session)) === false) {
                    throw new \Exception('Permission contructor parameter $session must either be null, or implement Lucid\Component\Container\ContainerInterface. If null is passed, then an instance of Lucid\Component\Container\SessionContainer will be instantiated instead and use $_SESSION for its source.');
                }
                $this->session = $session;
            }
        }
    }

    public function isLoggedIn(): bool
    {
        $id = $this->session->int($this->idField);
        return ($id > 0);
    }


    public function requireLogin()
    {
        if ($this->isLoggedIn() === false) {
            throw new \Exception('User was not logged in, but previous action required login');
        }
        return $this;
    }

    public function isAdmin(): bool
    {
        return $this->hasSessionValue('role_id', 1);
    }

    public function requireAdmin()
    {
        $this->requireSessionValue('role_id', 1);
    }

    public function hasSessionValue(string $name, $value): bool
    {
        $sessionValue = $this->session->get($name, null);
        return ($value == $sessionValue);
    }

    public function requireSessionValue(string $name, $reqValue)
    {
        if ($this->hasSessionValue($name, $reqValue) === false) {
            throw new \Exception('Permission denied. Required session variable '.$name.' to have value '.$reqValue.', but had '.$this->session->get($name, null));
        }
    }

    public function hasPermission(string ...$names): bool
    {
        $perms = $this->getPermissionsList();
        $allGood = true;
        foreach ($names as $name) {
            if (in_array($name, $perms) === false) {
                $allGood = false;
            }
        }
        return $allGood;
    }

    public function requirePermission(string ...$names)
    {
        if ($this->hasPermission(...$names) === false) {
            lucid::error()->permissionDenied();
        }
        return $this;
    }

    public function hasAnyPermission(string ...$names): bool
    {
        $perms = $this->getPermissionsList();
        $allGood = false;

        foreach ($names as $name) {
            if (in_array($name, $perms) === true) {
                $allGood = true;
            }
        }
        return $allGood;
    }

    public function requireAnyPermission(string ...$names)
    {
        if ($this->hasAnyPermission(...$names) === false) {
            throw new \Exception('User does not have any one of the required permissions: '.implode(', ', $names));
        }
        return $this;
    }

    public function getPermissionsList(): array
    {
        if ($this->session->has('permissions') === false || is_array($this->session->get('permissions')) === false) {
            $this->session->set('permissions', []);
        }
        return $this->session->get('permissions');
    }

    public function setPermissionsList(array $names=[])
    {
        $this->session->set('permissions', $names);
    }

    public function grant(string ...$names)
    {
        $current = $this->getPermissionsList();
        foreach ($names as $name) {
            array_push($current, $name);
        }
        $this->setPermissionsList(array_unique($current));
    }

    public function revoke(string ...$names)
    {
        $newPerms = [];
        $oldPerms = $this->getPermissionsList();
        foreach ($oldPerms as $oldPerm) {
            if (in_array($oldPerm, $names) === false) {
                $newPerms[] = $oldPerm;
            }
        }
        $this->setPermissionsList($newPerms);
    }
}
