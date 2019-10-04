<?php

namespace NTI\SecurityBundle\Controller\Secured;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\File\Exception\AccessDeniedException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Class SecuredController
 * @package NTI\SecurityBundle\Controller\Report
 * @Route("/secured")
 */
class SecuredController extends Controller {

    public function __construct(ContainerInterface $container) {
        $this->setContainer($container);
    }

    /**
     * @param Request $request
     * @return \Symfony\Component\HttpFoundation\Response
     * @Route("/denied", name="nti_secured_denied")
     */
    public function denied(Request $request) {
        if (0 === strpos($request->headers->get('Content-Type'), 'application/json'))return new JsonResponse(array("message"=> "access denied"), 403);
        $template = $this->container->hasParameter("nti_security.error_template") ? $this->getParameter("nti_security.error_template") : "NTISecurityBundle:Security:error403.html.twig";
        return $this->render($template);
    }
}