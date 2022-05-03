<?php

declare(strict_types=1);

namespace smalloyster\ValidationConstraint;

use DateTimeInterface;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class AudIssExp implements Constraint
{
	private string $issuer;
	private string $audience;
	private DateTimeInterface $expireTime;

	public function __construct(string $audience, string $issuer, DateTimeInterface $expireTime)
	{
		$this->audience = $audience;
		$this->issuer = $issuer;
		$this->expireTime = $expireTime;
	}

	public function assert(Token $token): void
	{
		if ($token->isExpired($this->expireTime)) {
			throw new ConstraintViolation(
				'The token is expired'
			);
		} elseif (!$token->hasBeenIssuedBy($this->issuer)) {
			throw new ConstraintViolation(
				'The token was not issued by the given issuers'
			);
		} elseif (!$token->isPermittedFor($this->audience)) {
			throw new ConstraintViolation(
				'The token is not allowed to be used by this audience'
			);
		}
	}
}
