<?php

namespace App\Controller;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\ContainerInterface as Container;
use Symfony\Component\HttpFoundation\Response;
use App\Security\LoginFormAuthenticator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Guard\GuardAuthenticatorHandler;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use App\Entity\User;
use App\Form\UserType;

class SecurityController extends AbstractController
{
    private $passwordEncoder;
    private $entityManager;
    public function __construct(UserPasswordEncoderInterface $passwordEncoder,EntityManagerInterface $entityManager,Container $container){
        $this->passwordEncoder = $passwordEncoder;
        $this->entityManager   = $entityManager;
        $this->contenedor   = $container;
    }

    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    public function logout()
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }


    public function new(Request $request,LoginFormAuthenticator $authenticator, GuardAuthenticatorHandler $guardHandler){
        $user = new User();
        
        $form = $this->createForm(UserType::class,$user);

        $form->handleRequest($request);
        $info=array();
        if ($form->isSubmitted() && $form->isValid()) {
            $user = $form->getData();
            $info=array(
                "status"=>'error',
                "msg"=>"Usuario ya se encuentra registrado"
            );
            if($this->searchUser($user->getEmail())){
                $user->setPassword($this->passwordEncoder->encodePassword($user,$user->getPassword()));
                $user->setRoles(['ROLE_USER']);
                $this->entityManager->persist($user);
                $this->entityManager->flush();
                return $guardHandler->authenticateUserAndHandleSuccess(
                    $user,          // the User object you just created
                    $request,
                    $authenticator, // authenticator whose onAuthenticationSuccess you want to use
                    'main'          // the name of your firewall in security.yaml
                );
            }
            // return $this->redirectToRoute('task_success');
        }

        return $this->render('security/newUser.html.twig', [
            'form' => $form->createView(),'info'=>$info
        ]); 
    }

    public function searchUser($user){
        $return=false;
        if(!empty($user)){
            $searchUser=$this->entityManager->getRepository(User::class)
                ->findOneBy(array('email'=>$user));
            if(!$searchUser){
                $return=true;
            }
        }
        return $return;
    }

}
