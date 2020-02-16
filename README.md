# smalloyster\jwt
封装好的一个php-jwt包，必须通过composer安装


# 基本使用
:one: 安装composer之后，执行以下命令
```
composer require smalloyster/jwt
```

:two: 在需要使用jwt的文件中引入此包
```
require_once 'vendor/autoload.php';

use smalloyster\Jwt;
```

:three: 复制以下代码，生成JWT-Token
```
$token = Jwt::getInstance()
	->setKey("your-jwt-key")
	->setIss("") // 自定义，签发者
	->setAud(""); // 自定义，接收者

// 可自定义payload的参数，定义data为一维数组即可
foreach ($data as $key => $value){
	$token = $token->setClaim($key, $value);
}

return (string)$token->encode();
```

:four: 验证JWT的签名有效性及使用者
```
$token = '';

return Jwt::getInstance()
	->setKey("your-jwt-key")
	->setIss("") // 自定义，签发者
	->setAud("") // 自定义，接收者
	->setToken($token)
	->verify();

上述将会返回一个数组：
JWT有效：["result" => true, "data" => payload中的数据]
JWT无效：["result" => false]
```
