<?php

class user extends Controller
{
    private $user;  //用户相关信息
    private $auth;  //用户所属组权限
    private $notCheck;
    function __construct(){
        parent::__construct();
        $this->tpl  = TEMPLATE  . 'user/';
        if(!isset($_SESSION)){//避免session不可写导致循环跳转
            $this->login("session write error!");
        }else{
            $this->user = &$_SESSION['kod_user'];
        }
        //不需要判断的action
        $this->notCheck = array('loginFirst','login','logout','loginSubmit','checkCode','public_link');
    }
    
    /**
     * 登陆状态检测;并初始化数据状态
     */
    public function loginCheck(){
        if(in_array(ACT,$this->notCheck)){//不需要判断的action
            return;
        }else if($_SESSION['kod_login']===true && $_SESSION['kod_user']['name']!=''){
            //$this->user['name'] is like 'u1/s8'
            define('USER',USER_PATH.$this->user['name'].'/');
            define('USER_TEMP',USER.'data/temp/');
//            define('USER_RECYCLE',USER.'recycle/');
            define('USER_RECYCLE',USER.'_runtime/');
            if (!file_exists(USER)) {
                header("X-Powered-By: diyMportal.");
                header('Content-Type: text/html; charset=utf-8');
                echo ('DIY微站目录不存在，请重试，如果始终失败，请反馈给我们。<a href="../mportal/index">返回微站列表</a>');
                exit;
            }
            define('MYHOME','/');
            define('HOME',USER.'diy/');
            $GLOBALS['web_root'] = str_replace(WEB_ROOT,'',HOME);//从服务器开始到用户目录
            $GLOBALS['is_root'] = 0;
            $this->config['user'] = $this->config['setting_default'];
            return;
        }else{
            header("X-Powered-By: diyMportal.");
            header('Content-Type: text/html; charset=utf-8');
            echo ('DIY微站管理会话超时了，请重试。<a href="../mportal/index">返回微站列表</a>');
            exit;
        }
    }

    //临时文件访问
    public function public_link(){
        load_class('mcrypt');
        $pass = $this->config['setting_system']['system_password'];
        $path = Mcrypt::decode($this->in['fid'],$pass);
        if (strlen($path) == 0) {
            show_json($this->L['error'],false);
        }
        file_put_out($path);
    }

    public function common_js(){
        $basic_path = BASIC_PATH;
        if (!$GLOBALS['is_root']) {
            $basic_path = '/';//对非root用户隐藏所有地址
        }
        $the_config = array(
            'lang'          => LANGUAGE_TYPE,
            'is_root'       => $GLOBALS['is_root'],
            'user_name'     => $this->user['name'],
            'web_root'      => $GLOBALS['web_root'],
            'web_host'      => HOST,
            'static_path'   => STATIC_PATH,
            'basic_path'    => $basic_path,
            'version'       => KOD_VERSION,
            'app_host'      => APPHOST,
            'office_server' => OFFICE_SERVER,
            'myhome'        => MYHOME,
            'upload_max'    => get_post_max(),
            'json_data'     => "",

            'theme'         => $this->config['user']['theme'], //列表排序依照的字段
            'list_type'     => $this->config['user']['list_type'], //列表排序依照的字段
            'sort_field'    => $this->config['user']['list_sort_field'], //列表排序依照的字段  
            'sort_order'    => $this->config['user']['list_sort_order'], //列表排序升序or降序
            'musictheme'    => $this->config['user']['musictheme'],
            'movietheme'    => $this->config['user']['movietheme']
        );

        $js  = 'LNG='.json_encode($GLOBALS['L']).';';
        $js .= 'AUTH='.json_encode($GLOBALS['auth']).';';
        $js .= 'G='.json_encode($the_config).';';
        header("Content-Type:application/javascript");
        echo $js;
    }
    
    /**
     * 登陆数据提交处理
     */
    public function loginSubmit(){
        if(!isset($this->in['token'])){
            header("X-Powered-By: diyMportal.");
            header('Content-Type: text/html; charset=utf-8');
            echo ('您的请求非法，请重试。<a href="../mportal/index">返回微站列表</a>');
            exit;
        }
        $token = $this->in['token'];
        load_class('mcrypt');

        $m = Mcrypt::decode($token, 'diymportal');
        $o = json_decode($m);
        if(!isset($o)){
            header("X-Powered-By: diyMportal.");
            header('Content-Type: text/html; charset=utf-8');
            echo ('出错了，可能是您的权限不足或者请求非法，请重试。<a href="../mportal/index">返回微站列表</a>');
            exit;
        }
        //{"uid":"1","id":"2","name":"\u6211\u65b0\u7684DIY\u5fae\u7ad9","pathname":"u1/s8"}

        $user = array('name' => $o->pathname, 'mportal' => $o->name, 'role' => 'default', 'status' => 1);
        session_start();//re start 有新的修改后调用
        $_SESSION['kod_login'] = true;
        $_SESSION['kod_user']= $user;
        setcookie('kod_name', $user['name'], time()+3600*4);

        header('location:./index.php');

//        if(!isset($this->in['name']) || !isset($this->in['password'])) {
//            $msg = $this->L['login_not_null'];
//        }else{
//            $name = rawurldecode($this->in['name']);
//            $password = rawurldecode($this->in['password']);
//
//            session_start();//re start 有新的修改后调用
//            $member = new fileCache(USER_SYSTEM.'member.php');
//            $user = $member->get($name);
//            if ($user ===false){
//                $msg = $this->L['user_not_exists'];
//            }else if(md5($password)==$user['password']){
//                $_SESSION['kod_login'] = true;
//                $_SESSION['kod_user']= $user;
//                setcookie('kod_name', $user['name'], time()+3600*24*365);
//                if ($this->in['rember_password'] == '1') {
//                    setcookie('kod_token',md5($user['password'].get_client_ip()),time()+3600*24*365);
//                }
//                header('location:./index.php');
//                return;
//            }else{
//                $msg = $this->L['password_error'];
//            }
//        }
//        $this->login($msg);
    }

    /**
     * 权限验证；统一入口检验
     */
    public function authCheck(){
        if (in_array(ACT,$this->notCheck)) return;
        if (!array_key_exists(ST,$this->config['role_setting']) ) return;
        if (!in_array(ACT,$this->config['role_setting'][ST]) &&
            ST.':'.ACT != 'user:common_js') return;//输出处理过的权限

        //有权限限制的函数
        $key = ST.':'.ACT;
        $group  = new fileCache(USER_SYSTEM.'group.php');
        $auth= $group->get($this->user['role']);
        

        //向下版本兼容处理
        //未定义；新版本首次使用默认开放的功能
        if(!isset($auth['userShare:set'])){
            $auth['userShare:set'] = 1;
        }
        if(!isset($auth['explorer:fileDownload'])){
            $auth['explorer:fileDownload'] = 1;
        }
        //默认扩展功能 等价权限
        $auth['user:common_js'] = 1;//权限数据配置后输出到前端
        $auth['explorer:pathChmod']         = $auth['explorer:pathRname'];
        $auth['explorer:pathDeleteRecycle'] = $auth['explorer:pathDelete'];
        $auth['explorer:pathCopyDrag']      = $auth['explorer:pathCuteDrag'];
        
        $auth['explorer:fileDownloadRemove']= $auth['explorer:fileDownload'];
        $auth['explorer:zipDownload']       = $auth['explorer:fileDownload'];
        $auth['explorer:fileProxy']         = $auth['explorer:fileDownload'];
        $auth['editor:fileGet']             = $auth['explorer:fileDownload'];
        $auth['explorer:makeFileProxy']     = $auth['explorer:fileDownload'];
        $auth['userShare:del']              = $auth['userShare:set'];
        if ($auth[$key] != 1) show_json($this->L['no_permission'],false);

        $GLOBALS['auth'] = $auth;//全局
        //扩展名限制：新建文件&上传文件&重命名文件&保存文件&zip解压文件
        $check_arr = array(
            'mkfile'    =>  $this->check_key('path'),
            'pathRname' =>  $this->check_key('rname_to'),
            'fileUpload'=>  isset($_FILES['file']['name'])?$_FILES['file']['name']:'',
            'fileSave'  =>  $this->check_key('path')
        );
        if (array_key_exists(ACT,$check_arr) && !checkExt($check_arr[ACT])){
            show_json($this->L['no_permission_ext'],false);
        }
    }

    private function check_key($key){
        return isset($this->in[$key])? rawurldecode($this->in[$key]):'';
    }

    public function checkCode() {
        session_start();//re start
        $code = rand_string(4);
        $_SESSION['check_code'] = strtolower($code);
        check_code($code);
    }
}