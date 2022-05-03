<?php

/**
 * @name PHP-JWT-helper
 * @package smalloyster
 * @author Oyster Cheung <master@xshgzs.com>
 * @since 2020-02-13
 * @version 2.0.0 2022-05-03
 */

namespace smalloyster;

use DateTimeImmutable;
use DateTimeZone;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\Clock\SystemClock;
use smalloyster\ValidationConstraint\AudIssExp;

class Jwt
{
	/**
	 * token令牌
	 * @var string
	 */
	private $token = '';

	/**
	 * 签发者
	 * @var string
	 */
	private $iss = '';

	/**
	 * 接收者
	 * @var string
	 */
	private $aud = '';

	/**
	 * 自定义参数
	 * @var array
	 */
	private $claims = [];

	/**
	 * 过期时间 默认7200s
	 * @var int
	 */
	private $expire = 7200;

	/**
	 * 密钥
	 * @var string
	 */
	private $key = '';

	/**
	 * 加密算法ID
	 * @var string
	 */
	private $algorithmId = 'HS256';

	/**
	 * 实例
	 * @var
	 */
	private static $_instance;


	/**
	 * 获取实例
	 * @return self
	 */
	public static function getInstance(): self
	{
		if (!self::$_instance) {
			self::$_instance = new self();
		}
		return self::$_instance;
	}


	/**
	 * setIss 设置iss
	 * @param string $iss
	 * @return $this
	 */
	public function setIss(string $iss = '')
	{
		$this->iss = $iss;
		return $this;
	}


	/**
	 * setAud 设置aud
	 * @param string $aud
	 * @return $this
	 */
	public function setAud(string $aud = '')
	{
		$this->aud = $aud;
		return $this;
	}


	/**
	 * setClaim 设置自定义参数
	 * @param string $name 参数名
	 * @param string $value 值
	 * @return $this
	 */
	public function setClaim(string $name = '', string $value = '')
	{
		$this->claims[$name] = $value;
		return $this;
	}


	/**
	 * setExpire 设置超时时间
	 * @param int $expire
	 * @return $this
	 */
	public function setExpire(int $expire = 0)
	{
		$this->expire = $expire;
		return $this;
	}


	/**
	 * setKey 设置加密密钥
	 * @param string $key
	 * @return $this
	 */
	public function setKey(string $key = '')
	{
		$this->key = $key;
		return $this;
	}


	/**
	 * setToken 设置token
	 * @param string $token
	 * @return $this
	 */
	public function setToken(string $token = '')
	{
		$this->token = $token;
		return $this;
	}


	/**
	 * setAlgorithmId 设置加密算法
	 * @param string $algorithmId 加密算法ID
	 * @return $this
	 */
	public function setAlgorithmId(string $algorithmId = 'HS256')
	{
		$this->algorithmId = $algorithmId;
		return $this;
	}


	/**
	 * getSigner 获取Signer对象
	 * @return Signer
	 */
	private function getSigner(): Signer
	{
		switch ($this->algorithmId) {
			case 'HS256':
				$signerClassName = 'Lcobucci\JWT\Signer\Hmac\Sha256';
				break;
			case 'HS384':
				$signerClassName = 'Lcobucci\JWT\Signer\Hmac\Sha384';
				break;
			case 'HS512':
				$signerClassName = 'Lcobucci\JWT\Signer\Hmac\Sha512';
				break;
			default:
				$signerClassName = 'Lcobucci\JWT\Signer\Hmac\Sha256';
				break;
		}
		return new $signerClassName;
	}


	/**
	 * generate 生成token
	 * @return string JWT-Token值
	 */
	public function generate(): string
	{
		$time = new DateTimeImmutable();
		$config = Configuration::forSymmetricSigner($this->getSigner(), InMemory::plainText($this->key));

		$this->builder = $config->builder()
			->issuedBy($this->iss) // 设置ISS
			->expiresAt($time->modify('+' . $this->expire . ' seconds')->setTimezone(new DateTimeZone('Asia/Shanghai'))); // 设置EXP

		// 设置接收人
		if ($this->aud != '') $this->builder->permittedFor($this->aud);

		// 设置自定义参数(payload)
		foreach ($this->claims as $name => $value) {
			$this->builder->withClaim($name, $value);
		}

		return $this->builder->getToken($config->signer(), $config->signingKey())->toString();
	}


	/**
	 * verify 验证有效性(签名、有效期、AUD、ISS)
	 * @return array [布尔值结果,token数据/错误信息]
	 */
	public function verify(): array
	{
		$config = Configuration::forSymmetricSigner($this->getSigner(), InMemory::plainText($this->key));
		$token = $config->parser()->parse($this->token);

		$config->setValidationConstraints(new AudIssExp($this->aud, $this->iss, SystemClock::fromSystemTimezone()->now()));

		// token各方面校验（签名、AUD、ISS、EXP）
		try {
			$signer = $config->signer();
			$config->validator()->assert($token, ...$config->validationConstraints());

			if (!$signer->verify($token->signature()->hash(), $token->payload(), InMemory::plainText($this->key))) {
				// 验签
				return [
					'result' => false,
					'data' => [
						'errorMsg' => 'The token sign was invalid'
					]
				];
			}
		} catch (RequiredConstraintsViolated $e) {
			return [
				'result' => false,
				'data' => [
					'errorMsg' => $e->violations()[0]->getMessage()
				]
			];
		}

		return [
			'result' => true,
			'data' => $token->claims()->all()
		];
	}
}
