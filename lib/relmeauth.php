<?php

// from http://us.php.net/manual/en/security.magicquotes.disabling.php
if (get_magic_quotes_gpc()) {
  $process = array(&$_GET, &$_POST, &$_COOKIE, &$_REQUEST);
  while (list($key, $val) = each($process)) {
    foreach ($val as $k => $v) {
      unset($process[$key][$k]);
      if (is_array($v)) {
        $process[$key][stripslashes($k)] = $v;
        $process[] = &$process[$key][stripslashes($k)];
      } else {
        $process[$key][stripslashes($k)] = stripslashes($v);
      }
    }
  }
  unset($process);
}

require_once __DIR__.DIRECTORY_SEPARATOR.'cassis'.DIRECTORY_SEPARATOR.'cassis-loader.php'; 

ob_start(); 
// use composers autoload if it exists, or require directly if not
if (file_exists(dirname(__DIR__).DIRECTORY_SEPARATOR.'vendor'.DIRECTORY_SEPARATOR.'autoload.php')) {
  require dirname(__DIR__).DIRECTORY_SEPARATOR.'vendor'.DIRECTORY_SEPARATOR.'autoload.php';
} else {
  throw "Vendor libraries could not be found. have you tried installing with composer?";
}
require __DIR__.DIRECTORY_SEPARATOR.'config.php';

class relmeauth {
  function __construct() {
    session_start();
    //$this->tmhOAuth = new tmhOAuth(array('curl_followlocation' => true));
  }

  function is_loggedin() {
    // TODO: should have a timestamp expiry in here.
    return (isset($_SESSION['relmeauth']['name']));
  }

  function create_from_session() {
    global $providers;

    $config = $providers[$_SESSION['relmeauth']['provider']];

    // create tmhOAuth from session info
    $token = $_SESSION['relmeauth']['access']['oauth_token'];
    $secret = $_SESSION['relmeauth']['access']['oauth_token_secret'];
  }

  function get_supported_list($user_url) {

    //get the actual location of the URL
    $user_url = $this->deref_redirect($user_url);

    // first try to authenticate directly with the URL given
    if ($this->is_provider($user_url)) {
      $_SESSION['relmeauth']['direct'] = true;
      if ($this->authenticate_url($user_url)) {
        return true; // bail once something claims to authenticate
      }
      unset($_SESSION['relmeauth']['direct']);
    }

    // get the rel-me URLs from the given site
    $source_rels = $this->discover($user_url);

    if ($source_rels==false || count($source_rels) == 0) {
      return array(); // no rel-me links found, bail
    }

    $results = array();
    // see if any of the source rel-me URLs reciprocate - check rels in order
    // and then try authing it. needs to maintain more session state to resume.
    foreach ($source_rels as $rel => $details):
      // only bother to confirm rel-me etc. if we know how to auth the dest.
      if ($this->is_provider($rel) &&
          $this->confirm_rel($user_url, $rel)) {
        $results[$rel] = true;

      } else {
        $results[$rel] = false;
      }
    endforeach; // source_rels

    if(empty($results)){
        $this->error('None of your providers are supported. Tried ' . $source_rels . '.');
        return array();
    }
    return $results;
  }



  /**
   * check to see if we know how to OAuth a URL
   *
   * @return whether or not it's a provider we know how to deal with
   * @author Tantek Çelik
   */
  function is_provider($confirmed_rel) {
    global $providers;

    $provider = parse_url($confirmed_rel);
    if (array_key_exists($provider['host'], $providers)) {
       return true;
    }
    if (strpos($provider['host'], 'www.')===0) {
      $provider['host'] = substr($provider['host'],4);
      if (array_key_exists($provider['host'], $providers) &&
          $providers[$provider['host']]['ltrimdomain'] == 'www.')
      {
        return true;
      }
    }
    return false;
  }

  /**
   * Wrapper for the OAuth authentication process for a URL
   *
   * @return false if authentication failed
   * @author Matt Harris and Tantek Çelik
   */
  function authenticate_url($confirmed_rel) {
    $provider = $this->provider_obj_for_url($confirmed_rel);

    // If we don't have an authorization code then get one
    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->state;
    header('Location: '.$authUrl);
    exit;


  }

  function provider_obj_for_url($confirmed_rel){
    global $providers;

    if (!$this->is_provider($confirmed_rel)){
      return false;
    }

    $provider_parsed = parse_url($confirmed_rel);
    $config = $providers[ $provider_parsed['host'] ];
    switch($provider_parsed['host']){
    case 'github.com':
        $provider = new League\OAuth2\Client\Provider\Github([
            'clientId'      => $config['client_id'],
            'clientSecret'  => $config['client_secret'],
            'redirectUri'   => $this->here(),
            'scopes'        => [''],
        ]);
        break;
    }

    return $provider;
  }

  function code_to_token($confirmed_rel, $code, $state){

      $provider = $this->provider_obj_for_url($confirmed_rel);

    if (empty($state) || ($state !== $_SESSION['oauth2state'])) {

        unset($_SESSION['oauth2state']);
        exit('Invalid state');

    } else {

        // Try to get an access token (using the authorization code grant)
        $token = $provider->getAccessToken('authorization_code', [
            'code' => $code
        ]);

        // Use this to interact with an API on the users behalf
        //return $token->accessToken;
        return $token;

        // Use this to get a new access token if the old one expires
        //echo $token->refreshToken;

        // Unix timestamp of when the token will expire, and need refreshing
        //echo $token->expires;
    }

    
  }

  function check_user_match($confirmed_rel, $token) {

    $provider = $this->provider_obj_for_url($confirmed_rel);

    $provider_parsed = parse_url($confirmed_rel);
    switch($provider_parsed['host']){
    case 'github.com':
        try {
            $userDetails = $provider->getUserDetails($token);
            $path_exploded = explode("/", $provider_parsed['path']);

            return ($path_exploded[1] == $userDetails->nickname);

        } catch (Exception $e) {

            // Failed to get user details
            return false;
        }

    }

  }

  /**
   * Wrapper for the OAuth authentication process
   *
   * @return false upon failure
   * @author Matt Harris and Tantek Çelik
   */
  function authenticate($confirmed_rels) {
    global $providers;

    foreach ($confirmed_rels as $host => $details) :
      if (authenticate_url($host))
        return true;
    endforeach; // confirmed_rels

    $this->error('None of your providers are supported. Tried ' . implode(', ', array_keys($confirmed_rels)) . '.');
    return false;
  }

  function complete_oauth( $verifier ) {
    global $providers;

    if ( ! array_key_exists($_SESSION['relmeauth']['provider'], $providers) ) {
      $this->error('None of your providers are supported, or you might have cookies disabled.  Make sure your browser preferences are set to accept cookies and try again.');
      return false;
    }

    if ($_REQUEST['oauth_token'] !== $_SESSION['relmeauth']['token']) {
      $this->error("The oauth token you started with is different to the one returned. try closing the tabs and making the requests again.");
      return false;
    }

    $config = $providers[$_SESSION['relmeauth']['provider']];
    $ok = $this->request(
      array_merge(
        $config['keys'],
        array(
          'user_token' => $_SESSION['relmeauth']['token'],
          'user_secret' => $_SESSION['relmeauth']['secret']
        )
      ),
      'GET',
      $config['urls']['access'],
      array(
        'oauth_verifier' => $verifier
      )
    );
    unset($_SESSION['relmeauth']['token']);
    unset($_SESSION['relmeauth']['secret']);

    if ($ok) {
      // get the users token and secret
      $_SESSION['relmeauth']['access'] = $this->tmhOAuth->extract_params($this->tmhOAuth->response['response']);

      // FIXME: validate this is the user who requested.
      // At the moment if I use another users URL that rel=me to Twitter for example, it
      // will work for me - because all we do is go 'oh Twitter, sure, login there and you're good to go
      // the rel=me bit doesn't get confirmed it belongs to the user
      $this->verify( $config );
      $this->redirect();
    }
    $this->error("There was a problem authenticating with {$provider['host']}. Error {$this->tmhOAuth->response['code']}. Please try later.");
    return false;
  }

  function verify( &$config ) {
    global $providers;
    $config = $providers[$_SESSION['relmeauth']['provider']];

    $ok = $this->request(
      array_merge(
        $config['keys'],
        array(
          'user_token' => $_SESSION['relmeauth']['access']['oauth_token'],
          'user_secret' => $_SESSION['relmeauth']['access']['oauth_token_secret']
        )
      ),
      'GET',
      $config['urls']['verify']
    );

    $creds = json_decode($this->tmhOAuth->response['response'], true);

    $given = self::normalise_url($_SESSION['relmeauth']['url']);
    $found = self::normalise_url(self::expand_tco($creds[ $config['verify']['url'] ]));

    $_SESSION['relmeauth']['debug']['verify']['given'] = $given;
    $_SESSION['relmeauth']['debug']['verify']['found'] = $found;

    if ( $given != $found &&
         array_key_exists('url2', $_SESSION['relmeauth']))
    {
       $given = self::normalise_url($_SESSION['relmeauth']['url2']);
    }

    if ( $given == $found ||
        ($this->is_provider($given) && $_SESSION['relmeauth']['direct']))
    {
      $_SESSION['relmeauth']['name'] = $creds[ $config['verify']['name'] ];
      return true;
    } else {
      // destroy everything
      $provider = $_SESSION['relmeauth']['provider'];
      // unset($_SESSION['relmeauth']);
      $this->error("That isn't you! If it really is you, try signing out of {$provider}. Entered $given (". @$_SESSION['relmeauth']['url2'] . "), found $found.");
      return false;
    }
  }

  function error($message) {
    if ( ! isset( $_SESSION['relmeauth']['error'] ) ) {
      $_SESSION['relmeauth']['error'] = $message;
    } else {
      $_SESSION['relmeauth']['error'] .= ' ' . $message;
    }
  }

  /**
   * Print the last error message if there is one.
   *
   * @return void
   * @author Matt Harris
   */
  function printError() {
    if ( isset( $_SESSION['relmeauth']['error'] ) ) {
      echo '<div id="error">' .
        $_SESSION['relmeauth']['error'] . '</div>';
      unset($_SESSION['relmeauth']['error']);
    }
  }

  /**
   * Check one rel=me URLs obtained from the users URL and see
   * if it contains a rel=me which equals this user URL.
   *
   * @return true if URL rel-me reciprocation confirmed else false
   * @author Matt Harris and Tantek Çelik
   */
  function confirm_rel($user_url, $source_rel) {
    $othermes = $this->discover($source_rel, false);
    $_SESSION['relmeauth']['debug']['source_rels'][$source_rel] = $othermes;
    if (is_array( $othermes)) {
      $othermes = array_map(array('relmeauth', 'deref_redirect'), $othermes);
      $user_url = self::normalise_url($user_url);

      if (in_array($user_url, $othermes)) {
        $_SESSION['relmeauth']['debug']['matched'][] = $source_rel;
        return true;
      }
    }
    return false;
  }

  /**
   * Check one rel=me URLs obtained from the users URL and see
   * if it contains a rel=me which equals this user URL.
   *
   * @return true if URL rel-me reciprocation confirmed else false
   * @author Matt Harris and Tantek Çelik
   * Should really abstract confirms_rel() confirm_rel() and replace both
   */
  function confirms_rel($user_url, $local_url, $source_rel) {
    $othermes = $this->discover( $source_rel, false );
    $_SESSION['relmeauth']['debug']['source_rels'][$source_rel] = $othermes;
    if ( is_array( $othermes ) ) {
      $othermes = array_map(array('relmeauth', 'normalise_url'), $othermes);
      $user_url = self::normalise_url($user_url);
      $local_url = self::normalise_url($local_url);

      if (in_array($user_url, $othermes) ||
          in_array($local_url, $othermes)) {
        $_SESSION['relmeauth']['debug']['matched'][] = $source_rel;
        return true;
      }
    }
    return false;
  }


  /**
   * Go through the rel=me URLs obtained from the users URL and see
   * if any of those sites contain a rel=me which equals this user URL.
   *
   * @return URLs that have confirmed rel-me links back to user_url or false
   * @author Matt Harris and Tantek Çelik
   */
  function confirm_rels($user_url, $source_rels) {
    if (!is_array($source_rels)) {
      $this->error('No rels found.');
      return false;
    }

    $confirmed_rels = array();
    foreach ( $source_rels as $url => $text ) {
      if (confirm_rel($user_url, $url)) {
        $confirmed_rels[$url] = $text;
      }
    }
    if (count($confirmed_rels)>0) {
      return $confirmed_rels;
    }
    $this->error('No rels matched. Tried ' . implode(', ', array_keys($this->source_rels)));
    return false;
  }

  /**
   * Does the job of discovering rel="me" urls
   *
   * @return array of rel="me" urls for the given source URL
   * @author Matt Harris
   */
  function discover($source_url, $titles=true) {
    global $providers;

    //$this->tmhOAuth->request('GET', $source_url, array(), false);
    //if ($this->tmhOAuth->response['code'] != 200) {
      //$this->error('Was expecting a 200 and instead got a '
                   //. $this->tmhOAuth->response['code']);
      //error_log('got an unexpected response from ' . $source_url . ', '
      //. json_encode($this->tmhOAuth->response));
      //return false;
    //}
        $ch = curl_init($source_url);

        if(!$ch){
            $this->error('error with curl_init');
            return $source_url;
        }

        $agent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
        curl_setopt($ch, CURLOPT_USERAGENT, $agent);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $page_content = curl_exec($ch);

    libxml_use_internal_errors(true); // silence HTML parser warnings
    $doc = new DOMDocument();
    if ( ! $doc->loadHTML($page_content) ) {
      error_log('could not parse '.$source_url);
      $this->error('Looks like I can\'t do anything with ' . $source_url);
      return false;
    }

    $xpath = new DOMXPath($doc);
    $relmes = $xpath->query(xphasrel('me'));
    $base = self::real_url(
      self::html_base_href($xpath), $source_url
    );

    // get anything?
    if ( empty($relmes) ) {
      error_log('No rel-me tags found for ' . $source_url);
      return false;
    }

    // clean up the relmes
    $urls = [];
    foreach ($relmes as $rel) {
      $title = (string) $rel->getAttribute('title');
      $url = (string) $rel->getAttribute('href');
      $url = self::real_url($base, $url);
      if (empty($url))
        continue;
      $url = self::expand_tco($url);

      // trim extra trailing stuff from external profile URLs
      // workaround for providers failing to properly 301 to the shortest URL
      $provider = parse_url($url);
      if (array_key_exists($provider['host'], $providers))
      {
        $config = $providers[ $provider['host']];
        if (array_key_exists('rtrimprofile', $config)) {
          $url = rtrim($url,$config['rtrimprofile']);
        }
      }

      $title = empty($title) ? $url : $title;
      if ( $titles ) {
        $urls[ $url ] = $title;
      } else {
        $urls[] = $url;
      }
    }
    return $urls;
  }

  /**
   * Works out the base URL for the page for use when calculating relative and
   * absolute URLs. This function looks for the base element in the head of
   * the document and if found uses that as the html base href.
   *
   * @param string $simple_xml_element the SimpleXML representing the obtained HTML
   * @return the new base URL if found or empty string otherwise
   * @author Tantek Çelik
   */
  function html_base_href($xpath) {
    if ( ! $xpath)
      return '';

    $base_elements = $xpath->query('//head//base[@href]');
    return ( $base_elements && ( $base_elements->length > 0 ) ) ?
      $base_elements->item(0)->getAttribute('href') :
      '';
  }

  /**
   * Calculates the normalised URL for a given URL and base href. Absolute and
   * relative URLs are supported as well as full URIs.
   *
   * @param string $base the base href
   * @param string $url the URL to be normalised
   * @return void
   * @author Matt Harris and Tantek Çelik
   */
  function real_url($base, $url) {
    // has a protcol, and therefore assumed domain
    if (preg_matches('/^[\w-]+:/', $url)) {
/*
      $parsed = parse_url($url);
      if ($parsed['path']==='') { // fix-up domain only URLs with a path
        $url .= '/';
      }
*/
      return $url;
    }

    // absolute URL
    if ( $url[0] == '/' ) {
      $url_bits = parse_url($base);
      $host = $url_bits['scheme'] . '://' . $url_bits['host'];
      return $host . $url;
    }

    // inspect base, check we have the directory
    $path = substr($base, 0, strrpos($base, '/')) . '/';
    // relative URL

    // explode the url with relatives in it
    $url = explode('/', $path.$url);

    // remove the domain as we can't go higher than that
    $base = $url[0].'//'.$url[2].'/';
    array_splice($url, 0, 3);

    // process each folder
    // for every .. remove the previous non .. in the array
    $keys = array_keys($url, '..');
    foreach( $keys as $idx => $dir ) {
      // work out the new offset for ..
      $offset = $dir - ($idx * 2 + 1);

      if ($offset < 0 && $url[0] == '..') {
        array_splice($url, 0, 1);
      } elseif ( $offset < 0 ) {
        // need to know where the new .. are
        return self::real_url($base, implode('/', $url));
      } else {
        array_splice($url, $offset, 2);
      }
    }
    $url = implode('/', $url);
    $url = str_replace('./', '', $url);
    return $base . $url;
  }

  /**
   * try and convert the string to SimpleXML
   *
   * @param string $str the HTML
   * @return SimpleXMLElement or false on fail
   * @author Matt Harris
   */
  // TODO this was replaced by DOMDocument::loadHTML; remove this function?
  function toXML($str) {
    $xml = false;

    try {
      $xml = @ new SimpleXMLElement($str);
    } catch (Exception $e) {
      if ( stripos('String could not be parsed as XML', $e->getMessage()) ) {
        return false;
      }
    }
    return $xml;
  }

  /**
   * Run tidy on the given string if it is installed. This function configures
   * tidy to support HTML5.
   *
   * @param string $html the html to run through tidy.
   * @return the tidied html or false if tidy is not installed.
   * @author Matt Harris
   */
  // TODO this shouldn't be necessary anymore with DOMDocument::loadHTML, remove it?
  function tidy($html) {
    if ( class_exists('tidy') ) {
      $tidy = new tidy();
      $config = array(
        'bare'            => TRUE,
        'clean'           => TRUE,
        'indent'          => TRUE,
        'output-xml'      => TRUE, // 'output-xhtml'      => TRUE,
    // must be -xml to cleanup named entities that are ok in XHTML but not XML
        'wrap'            => 200,
        'hide-comments'   => TRUE,
        'new-blocklevel-tags' => implode(' ', array(
          'header', 'footer', 'article', 'section', 'aside', 'nav', 'figure',
        )),
        'new-inline-tags' => implode(' ', array(
          'mark', 'time', 'meter', 'progress',
        )),
      );
      $tidy->parseString( $html, $config, 'utf8' );
      $tidy->cleanRepair();
      $html = str_ireplace( '<wbr />','&shy;', (string)$tidy );
      unset($tidy);
      return $html;
    } else {
      $this->error('no tidy :(');
      // need some other way to clean here. html5lib?
      return $html;
    }
    return false;
  }

  /**
   * Twitter now shortens rel-me URLs and replaces them with their
   * t.co short links (even in the return value from
   * verify_credentials). For this specific case, issue a HEAD request
   * to find the real URL.
   *
   * @param string $url the original URL, possibly a t.co short-link
   * @return the expanded URL if found; otherwise the unmodified original URL
   * @author Kyle Mahan
   */
  function expand_tco($url) {
    if (strpos($url, '/t.co/')) {
      $this->tmhOAuth->request('HEAD', $url, array(), false);
      if ($this->tmhOAuth->response['code'] == 301
      || $this->tmhOAuth->response['code'] == 302) {
        $redirect_url = $this->tmhOAuth->response['info']['redirect_url'];
        if ($redirect_url) {
          return $redirect_url;
        }
      }
    }
    return $url;
  }

  function redirect($url=false) {
     $url = ! $url ? $this->here() : $url;
     header( "Location: $url" );
     die;
   }

  function here($withqs=false) {
     $url = sprintf('%s://%s%s',
       $_SERVER['SERVER_PORT'] == 80 ? 'http' : 'https',
       $_SERVER['SERVER_NAME'],
       $_SERVER['REQUEST_URI']
     );
     $parts = parse_url($url);
     $url = sprintf('%s://%s%s',
       $parts['scheme'],
       $parts['host'],
       $parts['path']
     );
     if ($withqs) {
       $url .= '?' . $url['query'];
     }
     return $url;
   }

   function normalise_url($url) {
     $parts = parse_url($url);
     if ( ! isset($parts['path']))
        $url = $url . '/';

     return strtolower($url);
   }

   function deref_redirect($url){
        $ch = curl_init($url);

        if(!$ch){
            $this->error('error with curl_init');
            return $url;
        }

        //$agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.73.11 (KHTML, like Gecko) Version/7.0.1 Safari/537.73.11';
        $agent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
        curl_setopt($ch, CURLOPT_USERAGENT, $agent);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $page_content = curl_exec($ch);

        $corrected_url =  curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);

        return self::normalise_url($corrected_url);
   }


    function clear_expired_codes(){
	    $files = glob(__DIR__ . '/codes/code.*');
	    if ($files) {			
            foreach ($files as $file) {
                $time = substr(strrchr($file, '.'), 1);

                if ($time < time()) {
                    if (file_exists($file)) {
                        unlink($file);
                    }
                }
            }
        }
    }


    function generate_code($redirect_uri, $client_id, $state, $scope, $me){
    //generate and store this data and a code,
        //return code
	    $expire = 120;  //2 minutes


        // seed with microseconds
        list($usec, $sec) = explode(' ', microtime());
        srand((float) $sec + ((float) $usec * 100000));
        $randval = rand();
        
        $code = md5($randval . $redirect_uri . $client_id . $state . $scope . $me);

        $code_data = array('code' => $code, 
            'redirect_uri' => $redirect_uri ,
            'client_id' => $client_id ,
            'state' => $state ,
            'scope' => $scope ,
            'me' => $me);

        $checksum = md5($code . $client_id. $redirect_uri);
		$file = __DIR__ . '/codes/code.' . preg_replace('/[^A-Z0-9\._-]/i', '', $client_id.'.'.$redirect_uri.'.'.$checksum) . '.' . (time() + $expire);
		$handle = fopen($file, 'w');
		fwrite($handle, serialize($code_data));

        return $code;
    }
    function validate_code($code, $redirect_uri, $client_id, $state){
        //validate this data matches stored code
        //if successful
        //  invalidate code as it has been used
        //  set headers and respond correctly (200 etc)
        $this->clear_expired_codes();
        $checksum = md5($code . $client_id. $redirect_uri);
		$files = glob( __DIR__ . '/codes/code.' . preg_replace('/[^A-Z0-9\._-]/i', '', $client_id.'.'.$redirect_uri.'.'.$checksum) . '.*');
		if ($files) {
			$handle = fopen($files[0], 'r');
      		
			$code_data_serialized = fread($handle, filesize($files[0]));
			
			fclose($handle);

		
			$code_data =  unserialize($code_data_serialized);
            if($code_data['code'] == $code && $code_data['client_id'] == $client_id && $code_data['state'] == $state){
                //TODO: return correct header
                header('HTTP/1.1 200 OK');
                header('Content-Type: application/x-www-form-urlencoded');
                echo 'me='.urlencode($code_data['me']) ;
                if($code_data['scope']){
                    echo '&scope='.urlencode($code_data['scope']) ;
                } else {
                    // we have used this code, we throw it away
                    unlink($files[0]);
                }
                exit();
            } else {
                //TODO: return some error header
                header('HTTP/1.1 500 OK');
                echo 'debug 2';
                exit();
            }
		} else {
            //TODO: return some error header
                header('HTTP/1.1 500 OK');
                echo 'debug 1' ."\n"; 

            exit();
        }
    }
}

?>
