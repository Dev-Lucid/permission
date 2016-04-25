<?php
namespace Lucid\Component\Permission;

class Permission implements PermissionInterface
{
    protected $config = [
        'idField' => 'user_id',
    ];
    protected $session;

    public function __construct($config = null, $session = null)
    {
        if (is_null($config) === false) {
            if (is_array($config) === true) {
                $this->config =& $config;
            } elseif (is_object($config) === true && in_array('ArrayAccess', class_implements($config)) === true) {
                $this->config = $config;
            } else {
                throw new \Exception('Permission constructor parameter $config must either be null, an array, or implement ArrayAccess.');
            }
        }
        if (is_null($session) === true) {
            $this->session = new \Lucid\Component\Container\SessionContainer();
        } else {
            if (is_array($session) === true) {
                $this->session = new \Lucid\Component\Container\Container();
                $this->session->setSource($session);
            } elseif (is_object($session) === true && in_array('ArrayAccess', class_implements($session)) === true) {
                $this->session = $session;
            } else {
                throw new \Exception('Permission constructor parameter $session must either be null, or implement ArrayAccess. If null is passed, then an instance of Lucid\Component\Container\SessionContainer will be instantiated instead and use $_SESSION for its source.');
            }
        }
    }

    public function isLoggedIn(): bool
    {
        $id = $this->session->int($this->config['idField']);
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
        if ($this->session->has($name) === false) {
            return false;
        }
        $sessionValue = $this->session->get($name);
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
            throw new \Exception('Permission denied. To perform this action, user must have the following permissions: '.implode(', ', $names));
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
