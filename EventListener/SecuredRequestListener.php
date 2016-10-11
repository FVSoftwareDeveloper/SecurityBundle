<?php

namespace NTI\SecurityBundle\EventListener;

use NTI\SecurityBundle\Controller\Secured\SecuredController;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
use Symfony\Component\Security\Acl\Util\ClassUtils;
use Symfony\Component\Security\Core\User\UserInterface;

class SecuredRequestListener {

    /** @var ContainerInterface $container */
    private $container;

    public function __construct(ContainerInterface $container) {
        $this->container = $container;
    }

    public function onKernelController(FilterControllerEvent $event) {
        $user = $this->getUser();
        if(!$user) {
            // If explicit deny then throw error
            return;
        }

        if (!is_array($controller = $event->getController())) {
            // If explicit deny then throw error
            return;
        }

        // Controller could be a proxy
        $fqcn = ClassUtils::getRealClass($controller[0]);
        $fqan = $fqcn."::".$controller[1];


        $explicitDeny = $this->container->hasParameter("nti_security.explicit_deny") ? ($this->container->getParameter("nti_security.explicit_deny") === true ? true : false) : true;
        $godRoles = $this->container->hasParameter("nti_security.god_roles") ? $this->container->getParameter("nti_security.god_roles") : array();
        $globals = $this->container->hasParameter("nti_security.global") && is_array($this->container->getParameter('nti_security.global')) ? $this->container->getParameter('nti_security.global') : array();
        $securedActions = $this->container->hasParameter('nti_security.secured_actions') && is_array($this->container->getParameter('nti_security.secured_actions')) ? $this->container->getParameter('nti_security.secured_actions') : array();

        foreach($user->getRoles() as $role) {
            if(in_array($role->getRole(), $godRoles)) {
                return; // Has god access
            }
        }

        $match = null;

        foreach($securedActions as $securedAction) {
            // If no fqan or roles is defined ignore it
            if (!isset($securedAction["fqan"]) || !isset($securedAction["roles"])) continue;
            if ($fqan != $securedAction["fqan"]) continue; // This is not the action you are looking for.
            $match = $securedAction;
        }

        if(null === $match && $explicitDeny) {
            $event->setController(array(new SecuredController($this->container), 'denied')); return; // No match, deny
        } elseif(null === $match && !$explicitDeny) {
            return; // No match, allow
        }

        $actionRoles = $match["roles"];

        // Handle inheritance
        if(isset($match["inherit"]) && is_array($match["inherit"])) {
            foreach($match["inherit"] as $inherit) {
                $inheritedRoles = $this->getInheritedRoles($securedActions, $inherit);
                $actionRoles = array_merge($actionRoles, $inheritedRoles);
            }
        }

        // Verify if user has permissions
        if($match["fqan"] == $fqan) {
            if(!array_diff(array_merge($globals, $actionRoles), $user->getRoles())) {
                return; // Has permissions
            }
        }

        // Deny
        $event->setController(array(new SecuredController($this->container), 'denied'));
    }

    public function getInheritedRoles($securedActions, $inherit) {
        foreach($securedActions as $action) {
            if(!isset($action["name"]) || $action["name"] != $inherit) continue; // Only interested in the inherited
            if(!isset($action["roles"]) || !is_array($action["roles"])) return array();

            // If this has inheritance handle it the same way
            if(isset($action["inherit"]) && $action["inherit"] != $inherit) {
                return array_merge($action["roles"], $this->getInheritedRoles($securedActions, $action["inherit"]));
            }

            // Else just return the action roles
            return $action["roles"];
        }
        return array();
    }


    /**
     * @return UserInterface|null
     */
    public function getUser()
    {

        if (null === $token = $this->container->get('security.token_storage')->getToken()) {
            // no authentication information is available
            return null;
        }

        /** @var UserInterface $user */
        if (!is_object($user = $token->getUser())) {
            // e.g. anonymous authentication
            return null;
        }

        return $user;
    }

}