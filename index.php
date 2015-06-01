<?php

require_once( __DIR__ . '/lib/relmeauth.php');
$relmeauth = new relmeauth();
$error = false;

if ( isset($_GET['code']) ) {
    // this is the code from the redirect from rel-me-auth provider
    // we need to verify this code is correct i
    // and then confirm the user is who they are supposed to be
    $provider_url = $_SESSION['relmeauth']['provider_url'];
    $token = $relmeauth->code_to_token( $provider_url, $_GET['code'], $_GET['state']);
    $success = $relmeauth->check_user_match( $provider_url, $token);
    if($success && isset($_SESSION['relmeauth']['redirect_uri'])){

        //generate code to return
        $scope = null;
        if(isset($_SESSION['relmeauth']['scope'])){
            $scope = $_SESSION['relmeauth']['scope'];
        }
        $state = null;
        if(isset($_SESSION['relmeauth']['state'])){
            $state = $_SESSION['relmeauth']['state'];
        }
        
        $redir = $_SESSION['relmeauth']['redirect_uri'];
        $client_id = $_SESSION['relmeauth']['client_id'];
        $me = $_SESSION['relmeauth']['url'];

        $code = $relmeauth->generate_code($redir, $client_id, $state, $scope, $me);

        if(strpos($redir, '?')){
            $redir .= '&code=' . urlencode($code);
        } else {
            $redir .= '?code=' . urlencode($code);
        }
        if($success && $state){
            $redir .= '&state=' .  urlencode($state);
        }
        $redir .= '&me=' .  urlencode($me);


        header('Location: '.$redir);
    }

} elseif ( isset($_POST['code']) ) {
    // this is the code to verify the code sent out by this service.

    $redirect_uri = $_POST['redirect_uri']  ;

    $client_id = $_POST['client_id']  ;

    $state = null;
    if(isset($_POST['state'])){
        $state = $_POST['state']  ;
    }

    //This has a side effect of outputting correct results so processing will end here
    $relmeauth->validate_code($_POST['code'], $redirect_uri, $client_id, $state);



} elseif ( isset($_GET['use']) ) {
    // this is for handling code after a user has selected their provider
    // provider list points to here with the specific provider in the GET['use']
    // we need to reconfirm that this provider is in fact in the list for this user
    // and then we can try to authenticate
    $user_url = $_SESSION['relmeauth']['url'];
    $provider_url = strip_tags( stripslashes( $_GET['use'] ) );

    // update stored scope with accepted scopes value
    //TODO: add this to the form correctly
    if(isset($_GET['scope'])){
        $_SESSION['relmeauth']['scope'] = $_GET['scope'] ;
        $scope = $_GET['scope'] ;
    }

    $list = $relmeauth->get_supported_list( $user_url);
    if($list[$provider_url]){
        $_SESSION['relmeauth']['provider_url'] = $provider_url;
        //this function redirect to the provider
        $relmeauth->authenticate_url( $provider_url);
    }
    //if not found we will end up showing the list of providers again
    // TODO: add an error message about this
    //
    

} elseif ( isset($_GET['me']) ) {
    // the user submitted their url to the site via indieauth, this request should include
    // a redirect_uri
  
    $user_url = strip_tags( stripslashes( $_GET['me'] ) );
    $user_site = parse_url($user_url);
    if (!isset($user_site['path']) || $user_sitep['path']==='') { // fix-up domain only URLs with a path
        $user_url = $user_url . '/';
    }
    $_SESSION['relmeauth']['url'] = $user_url;

    $redirect_uri = $_GET['redirect_uri']  ;
    $_SESSION['relmeauth']['redirect_uri'] = $redirect_uri;

    $client_id = $_GET['client_id']  ;
    $_SESSION['relmeauth']['client_id'] = $client_id;

    if(isset($_GET['state'])){
        $state = $_GET['state']  ;
        $_SESSION['relmeauth']['state'] = $state;
    }
    if(isset($_GET['response_type'])){
        $response_type = $_GET['response_type']  ;
        $_SESSION['relmeauth']['response_type'] = $response_type;
    }
    if(isset($_GET['scope'])){
        $scope = $_GET['scope'] ;
        $_SESSION['relmeauth']['scope'] = $scope;
    }
    $list = $relmeauth->get_supported_list( $user_url);

} elseif ( isset($_POST['url']) ) {
    //the user submitted their url to the site via the web page.  we don't have a redirect_uri here
    //so this is really just for testing
    
    // we don't want any actual logins to bleed over in to testing page
    unset($_SESSION['relmeauth']);

    $user_url = strip_tags( stripslashes( $_POST['url'] ) );

    $user_site = parse_url($user_url);
    if ($user_site['path']==='') { // fix-up domain only URLs with a path
        $user_url = $user_url . '/';
    }

    $_SESSION['relmeauth']['url'] = $user_url;
    //$_SESSION['relmeauth']['write'] = $_POST['write'];

    // discover relme on the url
    $list = $relmeauth->get_supported_list( $user_url);

}


?><!DOCTYPE html>
<html lang="en-US">
<head>
  <meta charset="utf-8" />
  <title>RelMeAuth prototype</title>
  <script src="cassis/cassis.js" type="text/javascript" charset="utf-8"></script>
  <style type="text/css" media="all">
    body {
      max-width: 960px;
      margin: 5em auto;
      padding:0 2em;
      font-size: 22px;
      font-family: Helvetica Neue, Helvetica, sans-serif;
    }
    form {
      text-align: center;
    }
    input[name="url"] {
      width: 10em;
      font-size: 100%;
    }
    button {
      font-size: 100%;
    }
    div#error {
      color: red;
      margin: 0.5em 0;
    }
    p.intro {
      font-size: 0.8em;
    }
    pre {
      font-size: 0.5em;
    }
    textarea { font:inherit; font-weight:normal; display:block }
    label#for-post { display:block; font-weight:bold }
    .supported {
      background-color: #33FF00;
      border-radius: 10px;
      border: 2px solid #009900;
      padding: 3px;
      display:inline-block;
    }
    .supported:hover{opacity:0.7; cursor:pointer;;}
    .supported:active{opacity:1.0;border-color:grey}
    .not-supported:after {content:'Not Supported';color:red;font-size:0.7em;}
    .scopes {font-weight:bold;}

  </style>
</head>

<body>
  <h1>RelMeAuth prototype</h1>
<?php if ($success) { ?>
  <p>SUCCESS! You verified</p>
<?php } /*endif;*/ ?>

      <?php $relmeauth->printError(); ?>
        <?php if(isset($list)){ ?>
            <?php if(isset( $client_id)) { ?>
                <p>The application <?php echo $client_id?> is requesting access to your site.
                <?php if( isset( $scope) ) { ?>
                    It is requesting additional permissions to 
                    <?php 
                    $scopes = explode(' ',$scope);
                    foreach($scopes as $one_scope){
                        echo '<div class="scopes">'.$one_scope.'</div> ';
                    } ?>
                <?php } else { ?>
                    It is attempting to Identify you only, no additional permissions are requested.
                <?php } ?>
                </p>
            <?php } ?>
        <p>Found these rel-me links
            <?php foreach($list as $url => $supported){
                if($supported){?>
                    <a class="supported" href="?use=<?php echo urlencode($url)?>">
                        <?php echo $url?>
                    </a>
                <?php } else { ?>
                    <div class="not-supported">
                        <?php echo $url?>
                    </div>
                <?php } ?>
            <?php } //end foreach url ?>
        </p>
      <?php } else { ?>
        <p>This is a working prototype of <a href="http://microformats.org/wiki/RelMeAuth">RelMeAuth</a>.</p>
        <p>This is purely a test user interface. If this had been an actual user interface,
          you wouldn't be wondering what the hell is going on, what is "my domain",
          who am I, and why do I exist.</p>
        <p>This is only a test.</p>
        <p>Enter your personal web address, click Sign In, and see what happens.</p>

        <form action="" method="POST">
          <label for="url">Your domain:</label>
          <input type="url" required="required" name="url" id="url" style="width:17em"
            autofocus="autofocus"
            value="<?php echo @$_SESSION['relmeauth']['url'] ?>" />
          <button type="submit">Sign In</button>
        </form>
      <?php } ?>


  <p>It is likely there are still errors and any issues should be reported on the
  <a href="http://github.com/dissolve/RelMeAuth">GitHub Project Page</a>. This code is maintained by
  @<a href="https://twitter.com/dissolve333" rel="me">dissolve333</a> </p>

</body>
<script type="text/javascript" charset="utf-8">
  document.forms[0].onsubmit = function() {
    $input = document.getElementById('url');
    if ($input.value.replace(/^\s+|\s+$/g,"") == 'http://yourdomain.com') {
      $input.value = '';
    }
    else {
      $input.value = webaddresstouri($input.value, true);
    }
  }
  $input = document.getElementById('url');
  $input.onfocus = function() {
    if (this.value.replace(/^\s+|\s+$/g,"") == 'http://yourdomain.com') {
      this.value = '';
    }
  }
  $input.onclick = function() {
    this.focus();
    this.select();
  }
  $input.onblur = function() {
    if (this.value.replace(/^\s+|\s+$/g,"") == '') {
      this.value = 'http://yourdomain.com';
    } else {
      this.value = webaddresstouri(this.value, true);
    }
  }
  $input.oninvalid = function() {
    this.value = webaddresstouri(this.value, true);
    if (this.willValidate) {
      this.setCustomValidity('');
      this.parentNode.submit();
      return false;
    } else if (document.getElementById('error')) {
        return;
    } else {
      $html = document.createElement("div");
      $html.id = 'error';
      $html.innerHTML = "Oops! looks like you didn't enter a URL. Try starting with http://";
      this.parentNode.appendChild($html)
    }
  }
</script>
</html>

