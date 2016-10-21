<?php

namespace App\Users;

use Doctrine\ORM\EntityManagerInterface;
use Nette;

class UserManager implements Nette\Security\IAuthenticator
{

	use Nette\SmartObject;

	/**
	 * @var \Doctrine\ORM\EntityManagerInterface
	 */
	private $em;

	public function __construct(EntityManagerInterface $em)
	{
		$this->em = $em;
	}

	/**
	 * Performs an authentication.
	 * @throws Nette\Security\AuthenticationException
	 */
	public function authenticate(array $credentials)
	{
		list($username, $password) = $credentials;

		/** @var User $user */
		$user = $this->em->getRepository(User::class)->findOneBy([
			'username' => $username,
		]);

		if (!$user) {
			throw new \Nette\Security\AuthenticationException('The username is incorrect.', self::IDENTITY_NOT_FOUND);
		} elseif (!$user->authenticate($password, 'Nette\Security\Passwords::verify')) {
			throw new \Nette\Security\AuthenticationException('The password is incorrect.', self::INVALID_CREDENTIAL);
		} elseif ($user->needRehash('Nette\Security\Passwords::needsRehash')) {
			$user->changePass($password, 'Nette\Security\Passwords::hash');
			$this->em->flush();
		}

		return $user;
	}

	/**
	 * Adds new user.
	 *
	 * @return void
	 * @throws \App\Users\Exceptions\DuplicateNameException
	 */
	public function add($username, $password)
	{
		$newUser = new \App\Users\User($username);
		$newUser->changePass($password, 'Nette\Security\Passwords::hash');
		$this->em->persist($newUser);

		try {
			$this->em->flush();
		} catch (\Doctrine\DBAL\Exception\UniqueConstraintViolationException $exc) {
			throw new \App\Users\Exceptions\DuplicateNameException;
		}
	}

}
