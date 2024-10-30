# 6.[網站漏洞原始碼分析](DVWA_5.md)

## command injection
- low
  - PHP isset() 函数
    - https://www.runoob.com/php/php-isset-function.html
    - https://www.w3schools.com/php/func_var_isset.asp
  - $_POST
    - https://www.w3schools.com/Php/php_superglobals_post.asp#:~:text=$_POST%20contains%20an%20array 
  - $_REQUEST == > PHP superglobal variable
    - 用來接收使用者填寫的資料(例如:FORM 表單) 
```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?> 
```
```
使用者輸入 ==> www.ksu.edu.tw
系統會執行 ==> ping  -c 4  www.ksu.edu.tw
```
```
使用者輸入 ==> www.ksu.edu.tw; ls
系統會執行 ==> ping  -c 4  www.ksu.edu.tw; ls
```
- medieum
```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Set blacklist 設定黑名單 ==> windows 的&&串接與linux的;都設定成空白
    $substitutions = array(
        '&&' => '',
        ';'  => '',
    );

    // Remove any of the charactars in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?>
```
```

使用者輸入 ==> www.ksu.edu.tw; ls
系統會執行 ==> ping  -c 4  www.ksu.edu.tw ls  ==> 無法執行
```
```
有效的攻擊手法
使用者輸入 ==> www.ksu.edu.tw | ls
系統會執行 ==> ping  -c 4  www.ksu.edu.tw | ls ==>攻擊成功
```
- high
```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = trim($_REQUEST[ 'ip' ]);

    // Set blacklist 設定更多黑名單
    $substitutions = array(
        '&'  => '',
        ';'  => '',
        '| ' => '',
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
        '||' => '',
    );

    // Remove any of the charactars in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?> 
```
```
無效的攻擊手法
使用者輸入 ==> www.ksu.edu.tw | ls
系統會執行 ==> ping  -c 4  www.ksu.edu.tw  ls ==>攻擊失敗
```
```
有效的攻擊手法
使用者輸入 ==> www.ksu.edu.tw | |  ls
系統會執行 ==> ping  -c 4  www.ksu.edu.tw  ls ==>攻擊成功
```
- impossible
```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $target = $_REQUEST[ 'ip' ];
    $target = stripslashes( $target );
    //輸入 ==> "   127.0.0.1  " ==> "127.0.0.1" 
    // Split the IP into 4 octects
    $octet = explode( ".", $target );
    //輸入 : "127.0.0.1"  ==>$octet[0] ==127,
    // Check IF each octet is an integer
    if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) {
        // If all 4 octets are int's put the IP back together.
        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];

        // Determine OS and execute the ping command.
        if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
            // Windows
            $cmd = shell_exec( 'ping  ' . $target );
        }
        else {
            // *nix
            $cmd = shell_exec( 'ping  -c 4 ' . $target );
        }

        // Feedback for the end user
        echo "<pre>{$cmd}</pre>";
    }
    else {
        // Ops. Let the user name theres a mistake
        echo '<pre>ERROR: You have entered an invalid IP.</pre>';
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?> 
```
