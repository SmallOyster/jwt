<?php
/**
 * @name PHP-JWT-helper
 * @package smalloyster
 * @author Jerry Cheung <master@xshgzs.com>
 * @since 2020-02-13
 * @version 1.1.0 2020-02-14
 */
namespace smalloyster;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\ValidationData;

class Jwt{
	/**
	 * token令牌
	 * @var string
	 */
	private $token = '';

	/**
	 * 签发域名
	 * @var string
	 */
	private $iss = '';

	/**
	 * 接收域名
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
	 * @var
	 */
	private $key = '';
	
	/**
	 * 解析器
	 * @var
	 */
	private $parser;

	/**
	 * 实例
	 * @var
	 */
	private static $_instance;

	private function __construct() {}
	private function __clone() {}


	/**
	 * 获取实例
	 * @return Token
	 */
	public static function getInstance() {
		if (!self::$_instance) {
			self::$_instance = new self();
		}
		return self::$_instance;
	}


	/**
	 * genToken 设置 token
	 * @return string
	 */
	public function genToken() {
		return (string)$this->token;
	}


	/**
	 * setIss 设置 iss
	 * @param string $iss
	 * @return $this
	 */
	public function setIss($iss = '') {
		$this->iss = $iss;
		return $this;
	}


	/**
	 * setAud 设置 aud
	 * @param string $aud
	 * @return $this
	 */
	public function setAud($aud = '') {
		$this->aud = $aud;
		return $this;
	}


	/**
	 * setClaim 设置自定义参数
	 * @param string $name 参数名
	 * @param string $value 值
	 * @return $this
	 */
	public function setClaim($name = '',$value = '') {
		$this->claims[$name] = $value;
		return $this;
	}


	/**
	 * setExpire 设置超时时间
	 * @param int $expire
	 * @return $this
	 */
	public function setExpire($expire = 0) {
		$this->expire = $expire;
		return $this;
	}


	/**
	 * setKey 设置加密密钥
	 * @param string $key
	 * @return $this
	 */
	public function setKey($key = '') {
		$this->key = $key;
		return $this;
	}


	/**
	 * setToken 设置token
	 * @param string $token
	 * @return $this
	 */
	public function setToken($token = '') {
		$this->token = $token;
		return $this;
	}


	/**
	 * encode 生成token
	 * @return string JWT-Token值
	 */
	public function encode() {
		$time = time();

		$this->token = (new Builder())
			->issuedBy($this->iss) // 配置发行人（ISS权利要求）
			->issuedAt($time) // token创建时间
			->expiresAt($time + $this->expire) // 设置过期时间
			->identifiedBy(sha1($this->iss)); // 当前token设置的标识
		
		// 设置接收人
		if($this->aud != '') $this->token->permittedFor($this->aud);

		// 设置自定义参数(payload)
		foreach ($this->claims as $name => $value) {
			$this->token->withClaim($name,$value);
		}

		return $this->token->getToken(new Sha256(), new Key($this->key));
	}


	/**
	 * jwt decode token
	 * @return bool
	 */
	public function decode() {
		if (!$this->parser) {
			$this->parser = (new Parser())->parse((string)$this->token);
		}

		return $this->parser;
	}


	/**
	 * verify 验证有效性(签名、有效期、ISS/AUD/JTI)
	 * @return array
	 */
	public function verify() {
		$verifySign = $this->decode()->verify(new Sha256(),$this->key);

		$data = new ValidationData();
		$data->setIssuer($this->iss);
		$data->setAudience($this->aud);
		$data->setId(sha1($this->iss));

		// 校验不通过，结束
		if ($this->parser->validate($data) != true || $verifySign != true) {
			return array(
				'result' => false
			);
		}

		// 将payload数据转化为数组形式
		$claimsObj = $this->decode()->getClaims();
		$claims = [];

		foreach($claimsObj as $name => $valueObj) {
			$claims[$name] = $valueObj->getValue();
		}
		
		return array(
			'result' => true,
			'data' => $claims
		);
	}
}
