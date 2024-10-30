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


# 日誌分析
```
docker run -p 8088:80 vulnerables/web-dvwa
[+] Starting mysql...
Starting MariaDB database server: mysqld.
[+] Starting apache
Starting Apache httpd web server: apache2AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 172.17.0.2. Set the 'ServerName' directive globally to suppress this message
.
==> /var/log/apache2/access.log <==

==> /var/log/apache2/error.log <==
[Wed Oct 30 05:33:22.940018 2024] [mpm_prefork:notice] [pid 294] AH00163: Apache/2.4.25 (Debian) configured -- resuming normal operations
[Wed Oct 30 05:33:22.940401 2024] [core:notice] [pid 294] AH00094: Command line: '/usr/sbin/apache2'

==> /var/log/apache2/other_vhosts_access.log <==

==> /var/log/apache2/access.log <==
172.17.0.1 - - [30/Oct/2024:05:33:51 +0000] "GET / HTTP/1.1" 302 479 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:33:51 +0000] "GET /login.php HTTP/1.1" 200 1048 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:33:51 +0000] "GET /dvwa/css/login.css HTTP/1.1" 200 741 "http://127.0.0.1:8088/login.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:33:51 +0000] "GET /dvwa/images/login_logo.png HTTP/1.1" 200 9375 "http://127.0.0.1:8088/login.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:33:51 +0000] "GET /favicon.ico HTTP/1.1" 200 1706 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:33:59 +0000] "POST /login.php HTTP/1.1" 302 337 "http://127.0.0.1:8088/login.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:33:59 +0000] "GET /setup.php HTTP/1.1" 200 2035 "http://127.0.0.1:8088/login.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:33:59 +0000] "GET /dvwa/css/main.css HTTP/1.1" 200 1446 "http://127.0.0.1:8088/setup.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:33:59 +0000] "GET /dvwa/js/dvwaPage.js HTTP/1.1" 200 815 "http://127.0.0.1:8088/setup.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:33:59 +0000] "GET /dvwa/images/logo.png HTTP/1.1" 200 5330 "http://127.0.0.1:8088/setup.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:33:59 +0000] "GET /dvwa/js/add_event_listeners.js HTTP/1.1" 200 625 "http://127.0.0.1:8088/setup.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:33:59 +0000] "GET /dvwa/images/spanner.png HTTP/1.1" 200 748 "http://127.0.0.1:8088/setup.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:34:02 +0000] "POST /setup.php HTTP/1.1" 302 337 "http://127.0.0.1:8088/setup.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:34:02 +0000] "GET /setup.php HTTP/1.1" 200 2170 "http://127.0.0.1:8088/setup.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"

==> /var/log/apache2/error.log <==
[Wed Oct 30 05:34:02.403333 2024] [:error] [pid 300] [client 172.17.0.1:38976] PHP Notice:  Constant DVWA_WEB_PAGE_TO_ROOT already defined in /var/www/html/dvwa/includes/DBMS/MySQL.php on line 9, referer: http://127.0.0.1:8088/setup.php

==> /var/log/apache2/access.log <==
172.17.0.1 - - [30/Oct/2024:05:34:07 +0000] "GET /login.php HTTP/1.1" 200 1049 "http://127.0.0.1:8088/setup.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:34:14 +0000] "POST /login.php HTTP/1.1" 302 337 "http://127.0.0.1:8088/login.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:34:14 +0000] "GET /index.php HTTP/1.1" 200 3036 "http://127.0.0.1:8088/login.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:37:05 +0000] "GET /vulnerabilities/exec/ HTTP/1.1" 200 1716 "http://127.0.0.1:8088/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:37:30 +0000] "POST /vulnerabilities/exec/ HTTP/1.1" 200 1931 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:37:44 +0000] "GET /vulnerabilities/view_source.php?id=exec&security=low HTTP/1.1" 200 1362 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:37:44 +0000] "GET /dvwa/css/source.css HTTP/1.1" 200 500 "http://127.0.0.1:8088/vulnerabilities/view_source.php?id=exec&security=low" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:37:50 +0000] "GET /vulnerabilities/view_source_all.php?id=exec HTTP/1.1" 200 2149 "http://127.0.0.1:8088/vulnerabilities/view_source.php?id=exec&security=low" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:51:31 +0000] "GET /security.php HTTP/1.1" 200 2457 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:51:31 +0000] "GET /dvwa/images/lock.png HTTP/1.1" 200 1045 "http://127.0.0.1:8088/security.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:51:34 +0000] "POST /security.php HTTP/1.1" 302 427 "http://127.0.0.1:8088/security.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:51:34 +0000] "GET /security.php HTTP/1.1" 200 2474 "http://127.0.0.1:8088/security.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:51:37 +0000] "GET /vulnerabilities/exec/ HTTP/1.1" 200 1717 "http://127.0.0.1:8088/security.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:51:45 +0000] "POST /vulnerabilities/exec/ HTTP/1.1" 200 1724 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"

==> /var/log/apache2/error.log <==
ping: unknown host

==> /var/log/apache2/access.log <==
172.17.0.1 - - [30/Oct/2024:05:51:50 +0000] "POST /vulnerabilities/exec/ HTTP/1.1" 200 1733 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:51:57 +0000] "GET /security.php HTTP/1.1" 200 2457 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:52:00 +0000] "POST /security.php HTTP/1.1" 302 425 "http://127.0.0.1:8088/security.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:52:00 +0000] "GET /security.php HTTP/1.1" 200 2469 "http://127.0.0.1:8088/security.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:52:05 +0000] "GET /vulnerabilities/exec/ HTTP/1.1" 200 1717 "http://127.0.0.1:8088/security.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:52:08 +0000] "POST /vulnerabilities/exec/ HTTP/1.1" 200 1919 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"

==> /var/log/apache2/error.log <==
ping: unknown host

==> /var/log/apache2/access.log <==
172.17.0.1 - - [30/Oct/2024:05:52:19 +0000] "POST /vulnerabilities/exec/ HTTP/1.1" 200 1732 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:52:41 +0000] "POST /vulnerabilities/exec/ HTTP/1.1" 200 1925 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"

==> /var/log/apache2/error.log <==
ping: unknown host

==> /var/log/apache2/access.log <==
172.17.0.1 - - [30/Oct/2024:05:52:55 +0000] "POST /vulnerabilities/exec/ HTTP/1.1" 200 1920 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"

==> /var/log/apache2/error.log <==
ping: unknown host

==> /var/log/apache2/access.log <==
172.17.0.1 - - [30/Oct/2024:05:53:07 +0000] "POST /vulnerabilities/exec/ HTTP/1.1" 200 1732 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:53:14 +0000] "GET /vulnerabilities/exec/ HTTP/1.1" 200 1716 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:53:18 +0000] "GET /security.php HTTP/1.1" 200 2456 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:53:22 +0000] "POST /security.php HTTP/1.1" 302 451 "http://127.0.0.1:8088/security.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:53:22 +0000] "GET /security.php HTTP/1.1" 200 2473 "http://127.0.0.1:8088/security.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:53:27 +0000] "GET /vulnerabilities/exec/ HTTP/1.1" 200 1774 "http://127.0.0.1:8088/security.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:53:31 +0000] "POST /vulnerabilities/exec/ HTTP/1.1" 200 1807 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
172.17.0.1 - - [30/Oct/2024:05:54:26 +0000] "GET /vulnerabilities/view_source.php?id=exec&security=impossible HTTP/1.1" 200 1798 "http://127.0.0.1:8088/vulnerabilities/exec/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
```
