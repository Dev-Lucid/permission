<?php
namespace Lucid\Component\Permission;

class Permission implements PermissionInterface
{
    public $idField = 'user_id';
    protected $session;

    public function __construct($session = null)
    {
        if (is_null($session) === true) {
            $this->session = new \Lucid\Component\Store\Store($_SESSION);
        } else {
            if (is_array($session) === true) {
                $this->session = new \Lucid\Component\Store\Store($_SESSION);
            } else {
                if (is_object($session) === false || in_array('Lucid\Component\Store\StoreInterface', class_implements($session)) === false) {
                    throw new \Exception('Permission contructor parameter $session must either be null, or implement Lucid\Component\Store\StoreInterface. If null is passed, then an instance of Lucid\Component\Store\Store will be instantiated instead and use $_SESSION for its source.');
                }
                $this->session = $session;
            }
        }
    }

    public function isLoggedIn(): bool
    {
        $id = $this->session->int(self::$idField);
        return ($id > 0);
    }

    public function requireLogin()
    {
        if ($this->isLoggedIn() === false) {
            throw new \Exception('User was not logged in, but previous action required login');
        }
        return $this;
    }

    public function __call($name, $parameters)
    {
        if (strpos($name, 'require_') === 0 && isset($parameters[0]) === true) {
            $name = substr($name, 8);
            $this->requireSessionValue($name, $parameters[0]);
            return $this;
        } else {
            throw new \Exception('Unknown security function call: '.$name.'. The DevLucid\Security class does allow calls to undefined methods if the follow the pattern ->require_$variable($value); (ex: ->require_role_id(5)). When the security object is used in this way, it looks for an offset named $variable in lucid::$session, and throws an error if its value does not equal $value. Calling the security object in this manner requires that the function name you\'re accessing start with require_, and be passed 1 argument (the value to check against).');
        }
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
            lucid::error()->permissionDenied();
        }
        return $this;
    }

    public function getPermissionsList(): array
    {
        if ($this->session->is_set('permissions') === false || is_array($this->session->get('permissions')) === false) {
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
