<?php
/************************************
EDS API SimplePHP Demo App

This PHP is meant for educational and testing purposes.
If you are starting to develop a robust, production, object oriented
app to access your EDS implementation then we recommend you use the
PHP Application Sample as your starting point.

Author: Claus Wolf <cwolf@ebsco.com>
Date: 2014-09-25
Copyright 2014 EBSCO Information Services

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*************************************/
?>
<?php
session_start();
$path = 'edsapi-simple-app.php';

class EBSCOException extends Exception { }

class Functions
{

    /*Error codes defined by EDS API*/
    const EDS_UNKNOWN_PARAMETER          = 100;
    const EDS_INCORRECT_PARAMETER_FORMAT = 101;
    const EDS_INVALID_PARAMETER_INDEX    = 102;
    const EDS_MISSING_PARAMETER          = 103;
    const EDS_AUTH_TOKEN_INVALID         = 104;
    const EDS_INCORRECT_ARGUMENTS_NUMBER = 105;
    const EDS_UNKNOWN_ERROR              = 106;
    const EDS_AUTH_TOKEN_MISSING         = 107;
    const EDS_SESSION_TOKEN_MISSING      = 108;
    const EDS_SESSION_TOKEN_INVALID      = 109;
    const EDS_INVALID_RECORD_FORMAT      = 110;
    const EDS_UNKNOWN_ACTION             = 111;
    const EDS_INVALID_ARGUMENT_VALUE     = 112;
    const EDS_CREATE_SESSION_ERROR       = 113;
    const EDS_REQUIRED_DATA_MISSING      = 114;
    const EDS_TRANSACTION_LOGGING_ERROR  = 115;
    const EDS_DUPLICATE_PARAMETER        = 116;
    const EDS_UNABLE_TO_AUTHENTICATE     = 117;
    const EDS_SEARCH_ERROR               = 118;
    const EDS_INVALID_PAGE_SIZE          = 119;
    const EDS_SESSION_SAVE_ERROR         = 120;
    const EDS_SESSION_ENDING_ERROR       = 121;
    const EDS_CACHING_RESULTSET_ERROR    = 122;

    /**
     * HTTP status codes constants
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
     */
    const HTTP_OK                    = 200;
    const HTTP_BAD_REQUEST           = 400;
    const HTTP_NOT_FOUND             = 404;
    const HTTP_INTERNAL_SERVER_ERROR = 500;
   // This app uses the REST version of the API (HTTP Post for Authenticate, and HTTP GET for other API calls)
    private static $end_point = 'http://eds-api.ebscohost.com/edsapi/rest';
    private static $authentication_end_point = 'https://eds-api.ebscohost.com/Authservice/rest';

   //Enter your credentials here
    private static $userID = "";
    private static $password = "";
    private static $interfaceID = "";
    private static $profile = "";
    private static $orgID = "";
    private static $guest ="y";

    public function isGuest(){
        $guest = self::$guest;
        return $guest;
    }

   // This function maps the radio buttons below the search box to the field codes expected by the API
    public function fieldCodeSelect($term){
        if($term=='Author'){
            return 'AU';
        }
        if($term == 'title'){
            return 'TI';
        }
        if($term == 'keyword'){
            return '';
        }
        else{
            return $term;
        }
    }
    /*
     * Get authentication token from appication scop
     * Check authToen's expiration
     * if expired get a new authToken and re-new the time stamp
     *
     * @param none
     *
     * @access public
     */
    public function getAuthToken(){
        $lockFile = fopen("lock.txt","r");
        $tokenFile =fopen("token.txt","r");
        while(!feof($tokenFile)){
            $authToken = rtrim(fgets($tokenFile),"\n");
            $timeout = fgets($tokenFile)-600;
            $timestamp = fgets($tokenFile);
        }
        fclose($tokenFile);
        if(time()-$timestamp>=$timeout){
            // Lock check.
            if(flock($lockFile, LOCK_EX)){
                $tokenFile = fopen("token.txt","w+");
                $result = $this->requestAuthenticationToken();
                fwrite($tokenFile, $result['authenticationToken']."\n");
                fwrite($tokenFile, $result['authenticationTimeout']."\n");
                fwrite($tokenFile, $result['authenticationTimeStamp']);
                fclose($tokenFile);
                return $result['authenticationToken'];
            }else{
                return $authToken;
            }
        }else{
            return $authToken;
        }
        fclose($lockFile);
    }
   // This function calls the UID Authenticate method using HTTP POST and fetches the auth token
    public function requestAuthenticationToken()
    {
        $url = self::$authentication_end_point . '/UIDAuth';
        $userID = self::$userID;
        $password = self::$password;
        $interfaceID = self::$interfaceID;

   // Add the body of the request. Important. UserId and Password are to the API profile
   // UserID: customer’s EDS API user ID
   // Password: customer’s EDS API password
   // InterfaceID: optional string, use “api” (check with Michelle)
        $params =<<<BODY
<UIDAuthRequestMessage xmlns="http://www.ebscohost.com/services/public/AuthService/Response/2012/06/01">
    <UserId>$userID</UserId>
    <Password>$password</Password>
    <InterfaceId>$interfaceID</InterfaceId>
</UIDAuthRequestMessage>
BODY;

        // Set the content type to 'application/xml'. Important, otherwise the server won't understand the request.
        $headers = array(
            'Content-Type: application/xml',
            'Conent-Length: ' . strlen($params)
        );

        $response = $this->sendHTTPRequest($url, $params, $headers, 'POST');
        $response = $this->buildAuthenticationToken($response);
        return $response;
    }

    // This function receives the XML response to the Authenticate method call, and creates a auth token
    private function buildAuthenticationToken($response)
     {
        $token = (string) $response->AuthToken;
        $timeout = (integer) $response->AuthTimeout;

        $result = array(
            'authenticationToken'   => $token,
            'authenticationTimeout' => $timeout,
            'authenticationTimeStamp'=> time()
        );
        return $result;
     }
     /**
     * Get session token for a profile
     * If session token is not available
     * a new session token will be generated
     *
     * @param Authentication token, Profile
     * @access public
     */
    public function getSessionToken($authenToken, $invalid='n'){
        $token = '';

         if(isset($_COOKIE['Guest'])){
               if($invalid=='y'){
                   $sessionToken = $this->requestSessionToken($authenToken);
                   $_SESSION['sessionToken']= $sessionToken;
               }
               $token = $_SESSION['sessionToken'];
        }else{
            $sessionToken = $this->requestSessionToken($authenToken);
            $_SESSION['sessionToken']=$sessionToken;
            setcookie("Guest", 'Coolie' , 0);
            $token = $sessionToken;
        }
        return $token;
    }
    // This function calls the CreateSession method using HTTP GET and fetches the session token
    public function requestSessionToken($authenToken)
    {
        $url = self::$end_point . '/CreateSession';
        $profile = self::$profile;
        $orgID = self::$orgID;
        $guest = self::$guest;

        // Add the HTTP query parameters
        // if you are a vendor working on behalf of a customer then “org” must be filled in per your agreement
        // please note proper use of the “guest” setting per Terms Of Use i.e. must be set to ‘y’ if you are not making sufficient effort to authenticate users to your institution
        $params = array(
            'profile' => $profile,
            'org'     => $orgID,
            'guest'   => $guest
        );

        $headers = array(
            'x-authenticationToken: ' . $authenToken
        );

        $response = $this->sendHTTPRequest($url, $params, $headers);
        $response = $this->buildSessionToken($response);
        return $response;
    }

    // This function receives the XML response to the CreateSession method call, and creates a session token
     private function buildSessionToken($response)
     {
        $token = (string) $response->SessionToken;
        return $token;
     }

      // This function calls the Search method with the user’s query
      public function requestSearch()
    {

     if(isset($_REQUEST['back'])&&isset($_SESSION['results'])){
          //Cach search response for further use
        $response=$_SESSION['results'];
        return $response;
     }else{
         try{
          $url = self::$end_point . '/Search';

        // Build  the arguments for the Search API method
        $lookfor = str_replace('"','',$_REQUEST['lookfor']);
        $search = array(
            'lookfor' => $lookfor,
            'type'    => $_REQUEST['type']
         );

       /*
        * Set search parameters for the Search API method
        */
       $start = isset($_REQUEST['page']) ? $_REQUEST['page'] : 1;
       $limit = isset($_REQUEST['limit'])?$_REQUEST['limit']:20;
       $sortBy = isset($_REQUEST['sortBy'])?$_REQUEST['sortBy']:'relevance';
       $amount = isset($_REQUEST['amount'])?$_REQUEST['amount']:'detailed';
       $mode = 'all';

       $query = array();

        // Basic search
        if(!empty($search['lookfor'])) {
            // escaping as needed
            $term = urldecode($search['lookfor']);
            $term = str_replace('"', '', $term); // Temporary
            $term = str_replace(',',"\,",$term);
            $term = str_replace(':', '\:', $term);
            $term = str_replace('(', '\(', $term);
            $term = str_replace(')', '\)', $term);
            $type = $search['type'];
            // Transform a Search type into an EBSCO search field code
            $tag = $this->fieldCodeSelect($type);
            if($tag!=null){
            $query_str = implode(":", array($tag, $term));
            }else{
            $query_str = $term;
            }
            $query["query"] = $query_str;

        // No search term, return an empty array
        } else {
            $results = array();
            return $results;
        }
        $query['action'] = array();
        array_push($query['action'], "GoToPage($start)");
        // Add the HTTP query params
        $params = array(
            'sort'           => $sortBy,
            'searchmode'     => $mode,
            'view'           => $amount,
            'includefacets'  => 'n',
            'resultsperpage' => $limit,
            'pagenumber'     => $start,
            'highlight'      => 'y'
        );

        $params = array_merge($params, $query);

        $authenticationToken = $this ->getAuthToken();
        $sessionToken = $this ->getSessionToken($authenticationToken);

        $headers = array(
                'x-authenticationToken: ' . $authenticationToken,
                'x-sessionToken: ' . $sessionToken
            );

        $response = '';
        try{

        $response = $this->sendHTTPRequest($url, $params, $headers);

        }catch(EBSCOException $e) {
            try {
                // Retry the request if there were authentication errors
                $code = $e->getCode();
                switch ($code) {
                    case Functions::EDS_AUTH_TOKEN_INVALID:
                        $_SESSION['authToken'] = $this->getAuthToken();
                        $_SESSION['sessionToken'] = $this ->getSessionToken($_SESSION['authToken'],'y');

                        return $this->requestSearch();

                        break;
                    case Functions::EDS_SESSION_TOKEN_INVALID:
                        $_SESSION['sessionToken'] = $this ->getSessionToken($authenticationToken,'y');

                        return $this->requestSearch();

                        break;
                    default:
                        $result = array(
                            'error' => $e->getMessage()
                        );
                        return $result;
                        break;
                }
            }  catch(Exception $e) {
                $result = array(
                    'error' => $e->getMessage()
                );
                return $result;
            }
        }
        $response = $this->buildSearch($response);

        //Cach search response for further use
        $_SESSION['results'] = $response;

        return $response;

      }catch(Exception $e) {
            $result = array(
                'error' => $e->getMessage()
            );
            return $result;
        }
     }
    }

    // This function uses the Search XML response to create an array that stores the search results data
     private function buildSearch($response)
    {
        $hits = (integer) $response->SearchResult->Statistics->TotalHits;

        $records = array();
        if ($hits > 0) {
            $records = $this->buildRecords($response);
        }

        $results = array(
            'recordCount' => $hits,
            'records'     => $records
        );

        return $results;
    }

    // This function uses the Search XML response to create an array of the records in the results page
    private function buildRecords($response)
    {
        $results = array();

        $records = $response->SearchResult->Data->Records->Record;
        foreach ($records as $record) {
            $result = array();
            $result['pubType'] = $record -> Header-> PubType?(string)$record ->Header-> PubType:'';
            $result['PubTypeId']= $record->Header->PubTypeId? (string) $record->Header->PubTypeId:'';
            $result['queryUrl'] = $response->SearchRequestGet->QueryString?(string)$response->SearchRequestGet->QueryString:'';
            $result['ResultId'] = $record->ResultId ? (integer) $record->ResultId : '';
            $result['DbId'] = $record->Header->DbId ? (string) $record->Header->DbId : '';
            $result['DbLabel'] = $record->Header->DbLabel ? (string) $record->Header->DbLabel:'';
            $result['An'] = $record->Header->An ? (string) $record->Header->An : '';
            $result['PLink'] = $record->PLink ? (string) $record->PLink : '';
            $result['PDF'] = $record->FullText->Links ? (string) $record->FullText->Links->Link->Type : '';
            $result['HTML'] = $record->FullText->Text->Availability? (string) $record->FullText->Text->Availability : '';
            if (!empty($record->ImageInfo->CoverArt)) {
                foreach ($record->ImageInfo->CoverArt as $image) {
                    $size = (string) $image->Size;
                    $target = (string) $image->Target;
                    $result['ImageInfo'][$size] = $target;
                }
            } else {
                $result['ImageInfo'] = '';
            }

            $result['FullText'] = $record->FullText ? (string) $record->FullText : '';

            if ($record->CustomLinks) {
                $result['CustomLinks'] = array();
                foreach ($record->CustomLinks->CustomLink as $customLink) {
                    $category = $customLink->Category ? (string) $customLink->Category : '';
                    $icon = $customLink->Icon ? (string) $customLink->Icon : '';
                    $mouseOverText = $customLink->MouseOverText ? (string) $customLink->MouseOverText : '';
                    $name = $customLink->Name ? (string) $customLink->Name : '';
                    $text = $customLink->Text ? (string) $customLink->Text : '';
                    $url = $customLink->Url ? (string) $customLink->Url : '';
                    $result['CustomLinks'][] = array(
                        'Category'      => $category,
                        'Icon'          => $icon,
                        'MouseOverText' => $mouseOverText,
                        'Name'          => $name,
                        'Text'          => $text,
                        'Url'           => $url
                    );
                }
             }

            if($record->Items) {
                $result['Items'] = array();
                foreach ($record->Items->Item as $item) {
                    $label = $item->Label ? (string) $item->Label : '';
                    $group = $item->Group ? (string) $item->Group : '';
                    $data = $item->Data ? (string) $item->Data : '';
                    $result['Items'][$group][] = array(
                        'Label' => $label,
                        'Group' => $group,
                        'Data'  => $this->toHTML($data, $group)
                    );
                }
            }
            $results[] = $result;
        }
        return $results;
    }

     // This function calls the Retrieve method with the AN and Database ID of the record that the user clicked on
     public function requestRetrieve()
    {
         try{
        $url = self::$end_point . '/Retrieve';

        $db = $_REQUEST['db'];
        $an = $_REQUEST['an'];
        $highlight = $_REQUEST['lookfor'];
        $highlight = str_replace(array(" ","&","-"),array(","),$highlight);

        $authenticationToken = $this ->getAuthToken();
        $sessionToken = $this ->getSessionToken($authenticationToken);

        $params = array(
            'an'        => $an,
            'dbid'      => $db,
            'highlightterms' => $highlight
        );

        $headers = array(
                'x-authenticationToken: ' . $authenticationToken,
                'x-sessionToken: ' . $sessionToken
         );

        $response="";
        try{
        $response = $this->sendHTTPRequest($url, $params, $headers);
        }catch(EBSCOException $e) {
            try {
                // Retry the request if there were authentication errors
                $code = $e->getCode();
                switch ($code) {
                    case Functions::EDS_AUTH_TOKEN_INVALID:
                        $_SESSION['authToken'] = $this->getAuthToken();
                        $_SESSION['sessionToken'] = $this ->getSessionToken($_SESSION['authToken'],'y');

                        return $this->requestRetrieve();

                        break;
                    case Functions::EDS_SESSION_TOKEN_INVALID:
                        $_SESSION['sessionToken'] = $this ->getSessionToken($authenticationToken,'y');

                        return $this->requestRetrieve();

                        break;
                    default:
                        $result = array(
                            'error' => $e->getMessage()
                        );
                        return $result;
                        break;
                }
            }  catch(Exception $e) {
                $result = array(
                    'error' => $e->getMessage()
                );
                return $result;
            }
        }
        $response = $this->buildRetrieve($response);
        return $response;
    } catch(Exception $e) {
            $result = array(
                'error' => $e->getMessage()
            );
            return $result;
        }
    }

    // This function uses the Retrieve XML response to create an array of the record in the detailed record page
    private function buildRetrieve($response)
    {
        $record = $response->Record;

        if ($record) {
            $record = $record[0]; // there is only one record
        }

        $result = array();
        $result['AccessLevel'] = $record->Header -> AccessLevel?(string)$record->Header -> AccessLevel:'';
        $result['pubType'] = $record -> Header-> PubType? (string)$record -> Header-> PubType:'';
        $result['PubTypeId']= $record->Header->PubTypeId? (string) $record->Header->PubTypeId:'';
        $result['DbId'] = $record->Header->DbId ? (string) $record->Header->DbId : '';
        $result['DbLabel'] = $record->Header->DbLabel ? (string) $record->Header->DbLabel:'';
        $result['An'] = $record->Header->An ? (string) $record->Header->An : '';
        $result['PLink'] = $record->PLink ? (string) $record->PLink : '';
        $result['pdflink'] = $record->FullText->Links ? (string) $record->FullText->Links->Link->Url : '';
        $result['PDF'] = $record->FullText->Links ? (string) $record->FullText->Links->Link->Type : '';
        $result['HTML'] = $record->FullText->Text->Availability? (string) $record->FullText->Text->Availability : '';
        $value = $record->FullText->Text->Value ? (string) $record->FullText->Text->Value : '';
        $result['htmllink'] = $this->toHTML($value,$group = '');
        if (!empty($record->ImageInfo->CoverArt)) {
            foreach ($record->ImageInfo->CoverArt as $image) {
                $size = (string) $image->Size;
                $target = (string) $image->Target;
                $result['ImageInfo'][$size] = $target;
            }
        } else {
            $result['ImageInfo'] = '';
        }
        $result['FullText'] = $record->FullText ? (string) $record->FullText : '';

        if ($record->CustomLinks) {
            $result['CustomLinks'] = array();
            foreach ($record->CustomLinks->CustomLink as $customLink) {
                $category = $customLink->Category ? (string) $customLink->Category : '';
                $icon = $customLink->Icon ? (string) $customLink->Icon : '';
                $mouseOverText = $customLink->MouseOverText ? (string) $customLink->MouseOverText : '';
                $name = $customLink->Name ? (string) $customLink->Name : '';
                $text = $customLink->Text ? (string) $customLink->Text : '';
                $url = $customLink->Url ? (string) $customLink->Url : '';
                $result['CustomLinks'][] = array(
                    'Category'      => $category,
                    'Icon'          => $icon,
                    'MouseOverText' => $mouseOverText,
                    'Name'          => $name,
                    'Text'          => $text,
                    'Url'           => $url
                );
            }
        }

        if($record->Items) {
            $result['Items'] = array();
            foreach ($record->Items->Item as $item) {
                $label = $item->Label ? (string) $item->Label : '';
                $group = $item->Group ? (string) $item->Group : '';
                $data = $item->Data ? (string) $item->Data : '';
                $result['Items'][] = array(
                    'Label' => $label,
                    'Group' => $group,
                    'Data'  => $this->toHTML($data, $group)
                );
            }
        }
        return $result;

    }

     // This function request the PDF fulltext of the record
    public function requestPDF(){

$record = $this->requestRetrieve();
        //Call Retrieve Method to get the PDF Link from the record
$pdfUrl = $record['pdflink'];
echo '<meta http-equiv="refresh" content="0;url='.$pdfUrl.'">';
    }

    // This function is used to actually send the HTTP request and fetch the XML response from the API server
    protected function sendHTTPRequest($url, $params = null, $headers = null, $method = 'GET')
    {
        $log = fopen('curl.log', 'w'); // for debugging cURL

        // Create a cURL instance
        $ch = curl_init();

        // Set the cURL options
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($ch, CURLOPT_VERBOSE, true);
        curl_setopt($ch, CURLOPT_STDERR, $log);  // for debugging cURL
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Temporary

        // Set the query parameters and the url
        if (empty($params)) {
            // Only Info request has empty parameters
            curl_setopt($ch, CURLOPT_URL, $url);
        } else {
            // GET method
            if ($method == 'GET') {
                $query = http_build_query($params);
                // replace query params like facet[0]=value with facet=value
                $query = preg_replace('/%5B(?:[0-9]|[1-9][0-9]+)%5D=/', '=', $query);
                $url .= '?' . $query;
                curl_setopt($ch, CURLOPT_URL, $url);
            // POST method
            } else {
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
            }
        }

        // Set the header
        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        // Send the request
        $response = curl_exec($ch);

        $response = $this->errorHandling($ch,$response,$log);

        return $response;
    }

  // This function replaces the non standard HTML tags in the API response with standard HTML
    private function toHTML($data, $group = '')
    {
        global $path;
        // Any group can be added here, but we only use Au (Author)
        // Other groups, not present here, won't be transformed to HTML links
        $allowed_searchlink_groups = array('Au','Su');
        $allowed_link_groups = array('URL');
        // Map xml tags to the HTML tags
        // This is just a small list, the total number of xml tags is far more greater
        $xml_to_html_tags = array(
            '<jsection'    => '<section',
            '</jsection'   => '</section',
            '<highlight'   => '<span class="highlight"',
            '<highligh'    => '<span class="highlight"', // Temporary bug fix
            '</highlight>' => '</span>', // Temporary bug fix
            '</highligh'   => '</span>',
            '<text'        => '<div',
            '</text'       => '</div',
            '<title'       => '<h2',
            '</title'      => '</h2',
            '<anid'        => '<p',
            '</anid'       => '</p',
            '<aug'         => '<strong',
            '</aug'        => '</strong',
            '<hd'          => '<h3',
            '</hd'         => '</h3',
            '<linebr'      => '<br',
            '</linebr'     => '',
            '<olist'       => '<ol',
            '</olist'      => '</ol',
            '<reflink'     => '<a',
            '</reflink'    => '</a',
            '<blist'       => '<p class="blist"',
            '</blist'      => '</p',
            '<bibl'        => '<a',
            '</bibl'       => '</a',
            '<bibtext'     => '<span',
            '</bibtext'    => '</span',
            '<ref'         => '<div class="ref"',
            '</ref'        => '</div',
            '<ulink'       => '<a',
            '</ulink'      => '</a',
            '<superscript' => '<sup',
            '</superscript'=> '</sup',
            '<relatesTo'   => '<sup',
            '</relatesTo'  => '</sup',
            '<script'      => '',
            '</script'     => ''
        );

        // Map xml types to Search types used by the UI
        $xml_to_search_types = array(
            'Au' => 'Author',
            'Su' => 'Subject'
        );

        //  The XML data is XML escaped, let's unescape html entities (e.g. &lt; => <)
        $data = html_entity_decode($data);

        // Start parsing the xml data
        if (!empty($data)) {
            // Replace the XML tags with HTML tags
            $search = array_keys($xml_to_html_tags);
            $replace = array_values($xml_to_html_tags);
            $data = str_replace($search, $replace, $data);

            // Temporary : fix unclosed tags
            $data = preg_replace('/<\/highlight/', '</span>', $data);
            $data = preg_replace('/<\/span>>/', '</span>', $data);
            $data = preg_replace('/<\/searchLink/', '</searchLink>', $data);
            $data = preg_replace('/<\/searchLink>>/', '</searchLink>', $data);

            // Parse searchLinks
            if (!empty($group) && in_array($group, $allowed_searchlink_groups)) {
                $type = $xml_to_search_types[$group];
                $link_xml = '/<searchLink fieldCode="([^"]*)" term="([^"]*)">/';
                $link_html = "<a href=\"$path?search=y&lookfor=$2&type=$1\">";  //replaced $path with "result.php"
                $data = preg_replace($link_xml, $link_html, $data);
                $data = str_replace('</searchLink>', '</a>', $data);
                $data = str_replace('<br />','; ',$data);
            }
             // Parse link
            if (!empty($group) && in_array($group, $allowed_link_groups)) {
                $link_xml = '/<link linkTarget="([^"]*)" linkTerm="([^"]*)" linkWindow="([^"]*)">/';
                $link_html = "<a name=\"$1\" href=\"$2\" target=\"$3\">";  //replaced $path with "result.php"
                $data = preg_replace($link_xml, $link_html, $data);
                $data = str_replace('</link>', '</a>', $data);
            }
            // Replace the rest of searchLinks with simple spans
            $link_xml = '/<searchLink fieldCode="([^\"]*)" term="%22([^\"]*)%22">/';
            $link_html = '<span>';
            $data = preg_replace($link_xml, $link_html, $data);
            $data = str_replace('</searchLink>', '</span>', $data);
             // Parse bibliography (anchors and links)
            $data = preg_replace('/<a idref="([^\"]*)"/', '<a href="edsapi-simple-app.php$1"', $data);
            $data = preg_replace('/<a id="([^\"]*)" idref="([^\"]*)" type="([^\"]*)"/', '<a id="$1" href="edsapi-simple-app.php$2"', $data);
        }
        return $data;
    }

    public function errorHandling($ch, $response,$log){
        // Parse the response
        // In case of errors, throw 2 type of exceptions
        // EBSCOException if the API returned an error message
        // Exception in all other cases. Should be improved for better handling
        if ($response === false) {
            fclose($log); // for debugging cURL
            throw new Exception(curl_error($ch));
            curl_close($ch);
        } else {
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            fclose($log);  // for debugging cURL
            curl_close($ch);
            switch ($code) {
                case self::HTTP_OK:
                    $xml = simplexml_load_string($response);
                    if ($xml === false) {
                         throw new Exception('Error while parsing the response.');
                    } else {
                        $xml = simplexml_load_string($response);
                         return $xml;
                    }
                    break;
                case self::HTTP_BAD_REQUEST:
                    $xml = simplexml_load_string($response);
                    if ($xml === false) {
                         throw new Exception('Error while parsing the response.');
                    } else {
                        // If the response is an API error
                        $error = ''; $code = 0;
                        $isError = isset($xml->ErrorNumber) || isset($xml->ErrorCode);
                        if ($isError) {
                            if (isset($xml->DetailedErrorDescription) && !empty($xml->DetailedErrorDescription)) {
                                $error = (string) $xml->DetailedErrorDescription;
                            } else if (isset($xml->ErrorDescription)) {
                                $error = (string) $xml->ErrorDescription;
                            } else if (isset($xml->Reason)) {
                                $error = (string) $xml->Reason;
                            }
                            if (isset($xml->ErrorNumber)) {
                                $code = (integer) $xml->ErrorNumber;
                            } else if (isset($xml->ErrorCode)) {
                                $code = (integer) $xml->ErrorCode;
                            }
                            throw new EBSCOException($error, $code);
                        } else {
                            throw new Exception('The request could not be understood by the server
                            due to malformed syntax. Modify your search before retrying.');
                        }
                    }
                    break;
                case self::HTTP_NOT_FOUND:
                    throw new Exception('The resource you are looking for might have been removed,
                        had its name changed, or is temporarily unavailable.');
                    break;
                case self::HTTP_INTERNAL_SERVER_ERROR:
                    throw new Exception('The server encountered an unexpected condition which prevented
                        it from fulfilling the request.');
                    break;
                // Other HTTP status codes
                default:
                    throw new Exception('Unexpected HTTP error.');
                    break;
            }
        }
    }
}
$api = new Functions();
/**

Initialize application

 **/
$lockfile = fopen("lock.txt","w+");
fclose($lockfile);
if(file_exists("token.txt")){

        }else{
            $tokenFile = fopen("token.txt","w+");
            $result = $api->requestAuthenticationToken();
            fwrite($tokenFile, $result['authenticationToken']."\n");
            fwrite($tokenFile, $result['authenticationTimeout']."\n");
            fwrite($tokenFile, $result['authenticationTimeStamp']);
            fclose($tokenFile);
        }

if(!isset($_COOKIE['Guest'])){
    $authToken = $api->getAuthToken();
    $api->getSessionToken($authToken);
}
/**

MAIN

Begin displaying the user interface

**/
?>

<!-- UIs -->
<html>
    <head>
        <!-- PDF -->
<?php
// Clicks on PDF links need to be handled seperately
 if(isset($_REQUEST['pdf'])){
  $api -> requestPDF();
 }else{ ?>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<?php } ?>
        <title>Simple PHP Demo</title>

		<style type="text/css">
			root {
				display: block;
			}
			.header{
			   border: 2px solid #cccccc;
			}
			.footer{
				 border: 2px solid lightgray;
			}
			.searchbox-container{
				 border: 2px solid lightgray;
			}
			.search-form{
				margin-left:15px;
			}
			.resultsList-container{
				 border: 2px solid lightgray;
			}
			.results{
				margin-top:15px;
			}
			.statistics{
				margin-left:15px;
			}
			.record-container{
				border: 2px solid lightgray;
				overflow: hidden;
			}
			.search-iframe{
				border: 2px solid lightgray;
				width: 1402px;
			}
			 .title {
				margin-bottom: 10px;
			}
			.abstract {
				font-style: italic;
				margin-bottom: 10px;
			}
			.authors {
				margin-bottom: 10px;
			}
			.subjects {
				margin-bottom: 10px;
			}
			.links {
				margin-bottom: 10px;
			}
			.custom-links {
				margin-bottom: 50px;
			}
			.result:nth-child(2n) {
				background-color: #EEEEEE;
			}
			.table{
				margin-left: 15px;
			}
			.table-row {
				border-bottom: 1px solid #EEEEEE;
				margin-bottom: 10px;
				padding-bottom: 10px;
			}
			.table-cell {
				display: table-cell;
				vertical-align: top;
			}
			.icon {
				background: url("http://imageserver.epnet.com/branding/demos/edsapi/sprites_32.png") no-repeat scroll left top transparent;
				display: inline-block;
				height: 32px;
				line-height: 32px;
				padding-left: 36px;
			}
			.icon.html {
				background-position: 0 -42px;
			}
			.icon.pdf {
				background-position: 0 -84px;
			}
			a:link {
				color: blue;
				text-decoration: none;
			}
			a:visited{
				text-decoration: none;
				 color: blue;
			}
			.highlight {
				font-weight: bold;
			}
			.topbar{
				background: #1079C9 ;
			   width: 100%;
			   height: 30px;
			   margin-top: 10px;
			   margin-bottom: 20px;
			}
			.table-cell-box {
				border: 2px solid #cccccc;
				list-style-type: none;
				padding: 5px;
			}
			.table-cell-box li {
				padding: 5px 0;
			}
			.span-15 {
				width: 590px;
				 float: left;
				margin-right: 10px;
			}
			.jacket {
				float: left;
			}
			.floatleft{
				float: left;
			}
		</style>
                <style>
.pt-icon { width: 70px; float: left; display: inline-block; background-image: url('http://imageserver.ebscohost.com/branding/demos/edsapi/PT_Sprite.png'); background-repeat: no-repeat; }
.pt-serialPeriodical { background-position: -30px -30px; height: 59px; }
.pt-newspaperArticle { background-position: -140px -30px; height: 51px; }
.pt-image { background-position: -245px -30px; height: 47px; }
.pt-videoRecording { background-position: -345px -30px; height: 63px; }
.pt-score { background-position: -445px -30px; height: 57px; }
.pt-audio { background-position: -545px -30px; height: 49px; }
.pt-map { background-position: -35px -120px; height: 45px; }
.pt-book { background-position: -140px -120px; height: 59px; }
.pt-kitObject { background-position: -245px -120px; height: 50px; }
.pt-academicJournal, .pt-unknown { background-position: -345px -120px; height: 57px; }
.pt-dissertation { background-position: -445px -120px; height: 63px; }
.pt-literaryMaterial, .pt-authors { background-position: -35px -215px; height: 55px; }
.pt-tableChart { background-position: -140px -215px; height: 49px; }
.pt-patent { background-position: -245px -215px; height: 56px; }
.pt-report { background-position: -345px -215px; height: 63px; }
.pt-reference, .pt-readersAdvisory { background-position: -445px -215px; height: 52px; }
.pt-governmentDocument { background-position: -545px -215px; height: 60px; }
.pt-editorialOpinion { background-position: -35px -305px; height: 47px; }
.pt-transcript { background-position: -140px -305px; height: 63px; }
.pt-review { background-position: -245px -305px; height: 48px; }
.pt-biography { background-position: -345px -305px; height: 53px; }
.pt-electronicResource { 	background-position: -445px -305px; height: 63px; }
.pt-recommendedReadsList { background-position: -540px -305px; height: 61px; }
.pt-pictureBookExtender { background-position: -35px -400px; height: 65px; }
.pt-grabAndGo { background-position: -140px -400px; height: 51px; }
.pt-featureArticle { background-position: -245px -400px; height: 65px; }
.pt-curricularConnection { background-position: -345px -400px; height: 65px; }
.pt-bookTalk { background-position: -455px -400px; height: 55px; }
.pt-bookDiscussionGuides { background-position: -545px -400px; height: 55px; }
.pt-awardWinner { background-position: -34px -500px; height: 70px; }
.pt-authorReadalike { background-position: -140px -500px; height: 60px; }
.pt-series { background-position: -245px -495px; height: 75px; }
.pt-ebook { background-position: -350px -510px; height: 60px; }
.pt-audiobook { background-position: -440px -510px; height: 60px; }
.pt-conference { background-position: -545px -505px; height: 70px; }
.pt-Poem { background-position: -35px -615px; height: 60px; }
.pt-ShortStory { background-position: -141px -620px; height: 55px; }
.pt-play{ background-position: -245px -620px; height: 50px; }
                </style>
	</head>
<body>

 <!-- Search Box UI -->
        <div class="searchbox-container">
<form class="search-form" action="<?php echo $path ?>" method="get">
    <p>
        <input type="text" name="lookfor" style="width: 350px;" id="lookfor" />
        <input type="hidden" name="search" value="y" />
        <input type="submit" value="Search" />
    </p>
    <table>
        <tr>
            <td>
                <input type="radio" id="type-keyword" name="type" value="keyword" checked="checked"/>
                <label for="type-keyword">Keyword</label>
            </td>
            <td>
                <input type="radio" id="type-author" name="type" value="Author" />
                <label for="type-author">Author</label>
            </td>
            <td>
                <input type="radio" id="type-title" name="type" value="title" />
                <label for="type-title">Title</label>
            </td>
            <?php if($api->isGuest()=='y'){ ?>
            <td style="width: 200px">

            </td>
            <td>
                <b>You are in guest mode</b>
            </td>
            <?php } ?>
        </tr>
    </table>
</form>
        </div>

<!-- Results List UI  -->
<?php if(isset($_REQUEST['search'])){

  $results  = $api ->  requestSearch();

  // Error
        if (isset($results['error'])) {
           $error = $results['error'];
           $results =  array();
        } else {
           $error = null;
        }

  $lookfor = str_replace('"','',$_REQUEST['lookfor']);
  $start = isset($_REQUEST['page']) ? $_REQUEST['page'] : 1;
  $limit = isset($_REQUEST['limit'])?$_REQUEST['limit']:20;

?>

 <!-- Display Result List -->
       <div id="results-container" class="resultsList-container">
              <h2 style="margin-left: 15px;">Results</h2>
              <?php if ($error) { ?>
                 <div class="error">
              <?php echo $error; ?>
                 </div>
              <?php } ?>

              <?php if (!empty($results)) { ?>

 <!--Display a summary of Totle hits, Search query and Number of records on the page -->
                 <div class="statistics">
                 Showing <strong><?php if($results['recordCount']>0){ echo ($start - 1) * $limit + 1;} else { echo 0; } ?>  - <?php if((($start - 1) * $limit + $limit)>=$results['recordCount']){ echo $results['recordCount']; } else { echo ($start - 1) * $limit + $limit;} ?></strong>
                 of <strong><?php echo $results['recordCount']; ?></strong>
                 for "<strong><?php echo $lookfor; ?></strong>"
                 </div><hr>
              <?php } ?>

  <!-- Display all results -->
          <div class="results table">
              <?php if (empty($results['records'])){ ?>

  <!-- If result is empty, a error massage will show up -->
              <div class="result table-row">
                <div class="table-cell">
                 <h2><i>No results were found.</i></h2>
                </div>
              </div>
              <?php } else {

  /* Fetch out results */
              foreach ($results['records'] as $result) { ?>
              <div class="result table-row">
                <div class="record-id table-cell">
<!-- Record ID --><?php echo $result['ResultId']; ?>.
                </div>

<!-- Pub Type --><?php if (!empty($result['pubType'])) { ?>
                <div class="pubtype table-cell" style="text-align: center">
                    <?php if (!empty($result['ImageInfo'])) {
                        $params = array(
                            'lookfor'=>$lookfor,
                            'type'=>$_REQUEST['type'],
                            'record'=>'y',
                            'db'=>$result['DbId'],
                            'an'=>$result['An']
                        );
                        $params = http_build_query($params);
                        ?>
                    <a href="<?php echo $path ?>?<?php echo $params ?>">
                                <img src="<?php echo $result['ImageInfo']['thumb']; ?>" />
                        </a>
                    <?php }else{
                     $pubTypeId =  $result['PubTypeId'];
                     $pubTypeClass = "pt-".$pubTypeId;
                    ?>
                    <span class="pt-icon <?php echo $pubTypeClass?>"></span>
                    <?php } ?>
                    <div><?php echo $result['pubType'] ?></div>
                </div>
                <?php } ?>
                <div class="info table-cell">
                    <div style="margin-left: 10px">

                    <div class="title">
                        <?php
                        $params = array(
                            'lookfor'=>$lookfor,
                            'type'=>$_REQUEST['type'],
                            'record'=>'y',
                            'db'=>$result['DbId'],
                            'an'=>$result['An']
                        );
                        $params = http_build_query($params);
                        ?>
<!-- Title -->          <?php if (!empty($result['Items']['Ti'])){
                         ?>
                        <?php foreach($result['Items']['Ti'] as $Ti){ ?>
                            <a href="<?php echo $path ?>?<?php echo $params ?>"><?php echo  $Ti['Data']; ?></a>
                           <?php } }
                            else {   ?>
                            <a href="<?php echo $path ?>?<?php echo $params ?>"><?php echo "Title is not Aavailable"; ?></a>
                       <?php     }
                            ?>
                    </div>
                    <?php if(!empty($result['Items']['TiAtl'])){ ?>
                    <div>
                        <?php foreach($result['Items']['TiAtl'] as $TiAtl){ ?>
                        <?php echo $TiAtl['Data']; ?>
                        <?php } ?>
                    </div>
                    <?php } ?>

<!-- Authors -->       <?php if (!empty($result['Items']['Au'])) { ?>
                        <div class="authors">
                            <span>
                               <table>
                                    <tr>
                                        <td style="vertical-align: top; width: 25px">By : </td><td>
                                            <table><tr><td>
                                    <?php foreach($result['Items']['Au'] as $Author){ ?>
                                        <?php echo $Author['Data']; ?>;
                                    <?php } ?>
                                            </td></tr>
                                            </table>
                                         </td></tr>
                                </table>
                            </span>
                        </div>
                      <?php } ?>

                      <?php if (isset($result['Items']['Src'])||isset($result['Items']['SrcInfo'])) { ?>
<!-- Source  -->       <?php if(isset($result['Items']['Src'])){ ?>
                       <div class="source">
                                <span>
                                    <?php foreach($result['Items']['Src'] as $src){
                                         echo $src['Data'];
                                     }?>
                                </span>
                        </div>
                       <?php } ?>
                       <?php if(isset($result['Items']['SrcInfo'])){ ?>
                        <div class="source">
                                <span>
                                    <?php foreach($result['Items']['SrcInfo'] as $src){
                                         echo $src['Data'];
                                     }?>
                                </span>
                        </div>
                       <?php } ?>
                          <br/>
                    <?php } ?>
                    <?php if (isset($result['Items']['Ab'])) { ?>
<!-- Abstract -->       <div class="abstract">
                            <table>
                                <tr>
                                    <td style="vertical-align: top;">Abstract: </td>
                                    <td>
                                        <table>
                                             <?php foreach($result['Items']['Ab'] as $Abstract){ ?>
                                            <tr>
                                                <td>
                                                    <?php echo $Abstract['Data']; ?>
                                                </td>
                                            </tr>
                                            <?php } ?>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    <?php } ?>

                    <?php if (!empty($result['Items']['Su'])) { ?>
<!-- Subject  -->       <div class="subjects">
                            <table>
                                <tr>
                                    <td style="vertical-align: top;">Subjects:</td>
                                    <td>
                                        <table>
                                            <tr><td>
                                             <?php foreach($result['Items']['Su'] as $Subject){ ?>
                                            <?php echo $Subject['Data']; ?>;
                                             <?php } ?>
                                           </td></tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    <?php } ?>

                    <div class="fulltext">
<!-- HTML Fulltext  -->  <?php if($result['HTML']==1){?>
                         <?php if($api->isGuest()=='y'){ ?>
                         <a target="_blank"  class="icon html fulltext" href="<?php echo $result['PLink'] ?>">Full Text</a>
                         <?php } ?>
                         <?php if($api->isGuest()=='n'){ ?>
                         <a target="_blank"  class="icon html fulltext" href="<?php echo $path ?>?record=y&an=<?php echo $result['An']; ?>&db=<?php echo $result['DbId']; ?>&lookfor=<?php echo $lookfor ?>&type=<?php echo $_REQUEST['type']?>#html">Full Text</a>
                        <?php } }?>

<!-- PDF Fulltext  -->   <?php if(!empty($result['PDF'])){?>
                         <?php if($api->isGuest()=='y'){ ?>
                         <a target="_blank" class="icon pdf fulltext" href="<?php echo $result['PLink'] ?>">Full Text</a>
                         <?php } ?>
                         <?php if($api->isGuest()=='n'){ ?>
                         <a target="_blank" class="icon pdf fulltext" href="<?php echo $path ?>?pdf=y&an=<?php echo $result['An']?>&db=<?php echo $result['DbId']?>">Full Text</a>
                         <?php } }?>
                    </div>

                    <?php if (!empty($result['CustomLinks'])){ ?>
<!-- Custom Links --> <div class="custom-links">
                    <?php if (count($result['CustomLinks'])<=3){?>

                            <?php foreach ($result['CustomLinks'] as $customLink) { ?>
                                <p>
                                 <a href="<?php echo $customLink['Url']; ?>" title="<?php echo $customLink['MouseOverText']; ?>">
                                     <img src="<?php echo $customLink['Icon'] ?>"/>
                                     <?php echo $customLink['Name']; ?>
                                 </a>
                                </p>
                            <?php } ?>

                    <?php } else {?>

                            <?php for($i=0; $i<3 ; $i++){
                                $customLink = $result['CustomLinks'][$i];
                                ?>
                                <p>
                                   <a href="<?php echo $customLink['Url']; ?>" title="<?php echo $customLink['MouseOverText']; ?>"><?php echo $customLink['Name']; ?></a>
                                </p>
                            <?php } }?>
                    </div>
                    <?php } ?>
                    <?php if (!empty($result['FullTextCustomLinks'])){ ?>
                    <div class="custom-links">
                    <?php if (count($result['FullTextCustomLinks'])<=3){?>
                            <?php foreach ($result['FullTextCustomLinks'] as $customLink) { ?>
                                <p>
                                 <a href="<?php echo $customLink['Url']; ?>" title="<?php echo $customLink['MouseOverText']; ?>"><img src="<?php echo $customLink['Icon']?>" /> <?php echo $customLink['Name']; ?></a>
                                </p>
                            <?php } ?>
                    <?php } else {?>
                            <?php for($i=0; $i<3 ; $i++){
                                $customLink = $result['FullTextCustomLinks'][$i];
                                ?>
                                <p>
                                   <a href="<?php echo $customLink['Url']; ?>" title="<?php echo $customLink['MouseOverText']; ?>"><?php echo $customLink['Name']; ?></a>
                                </p>
                            <?php } ?>

                    <?php } ?>
                    </div>
                    <?php } ?>
                </div>
                </div>
            </div>
        <?php } } ?>
    </div>
    </div>
 <?php } ?>

 <!-- Retrieve UI -->
 <?php if(isset($_REQUEST['record'])){

$result = $api->requestRetrieve();

// Set error
if (isset($result['error'])) {
    $error = $result['error'];
} else {
    $error = null;
}
?>

<!-- Display Record  -->
    <div id="record-container" class="record-container">
     <div class ="topbar">
         <?php
         $params = array(
         'lookfor'=>$_REQUEST['lookfor'],
         'type'=>$_REQUEST['type'],
         'back'=>'y',
         'search'=>'y'
         );
         $params = http_build_query($params);
         ?>
       <div style="padding-top: 6px; float: left" ><a style="color: #ffffff;margin-left: 15px;" href="<?php echo $path ?>?<?php echo $params ?>"> << Back to Results</a></div>
     </div>

<!-- Display record data -->
     <div class="table">
     <?php if ($error) { ?>
     <div class="error">
        <?php echo $error; ?>
     </div>
     <?php } ?>

<!-- Top Title -->
     <h1>
       <?php if(isset($result['Items'])){
           echo $result['Items'][0]['Data'];
       } ?>
    </h1>

 <!-- Full Text&Links -->
         <div>
             <div class="table-cell floatleft">
                 <?php if(!empty($result['PLink'])){?>
                 <ul class="table-cell-box">
                      <li>
                          <a href="<?php echo $result['PLink'] ?>">
                        View in EDS
                        </a>
                      </li>
                  </ul>
                      <?php } ?>

                     <?php if(!empty($result['PDF'])||$result['HTML']==1){?>
                     <ul class="table-cell-box">
                     <label>Full Text:</label><hr/>

                     <?php if(!empty($result['PDF'])){?>
                      <li>
                          <?php if($api->isGuest()=='y'){ ?>
                          <a target="_blank" class="icon pdf fulltext" href="<?php echo $result['PLink']?>">Full Text</a>
                          <?php } ?>
                          <?php if($api->isGuest()=='n'){ ?>
                          <a target="_blank" class="icon pdf fulltext" href="PDF.php?an=<?php echo $result['An']?>&db=<?php echo $result['DbId']?>">
                        Full Text
                        </a>
                          <?php } ?>
                      </li>
                      <?php } ?>
                      <?php if($result['HTML']==1){ ?>
                       <?php if($api->isGuest()=='y'){ ?>
                      <li>
                          <a class="icon html fulltext" href="<?php echo $result['PLink']?>">Full Text</a>
                      </li>
                          <?php } ?>
                           <?php if($api->isGuest()=='n'){ ?>
                      <li>
                          <a target="_blank" class="icon html fulltext" href="#html">Full Text</a>
                      </li>
                         <?php } ?>
                      <?php } ?>
                      </ul>
                      <?php } ?>

                      <?php if (!empty($result['CustomLinks'])) { ?>
                      <ul class="table-cell-box">
                          <label>Custom Links:</label><hr/>
                            <?php foreach ($result['CustomLinks'] as $customLink) { ?>
                                <li>
                                    <a href="<?php echo $customLink['Url']; ?>" title="<?php echo $customLink['MouseOverText']; ?>"><img src="<?php echo $customLink['Icon']?>" /> <?php echo $customLink['Text']; ?></a>
                                </li>
                            <?php } ?>
                       </ul>
                      <?php } ?>

             </div>

 <!-- Fetch out all record data -->
             <div id="span-15" style="margin-left: 20px" class="table-cell span-15">
                 <table>
       <?php if (!empty($result['Items'])) { ?>

                     <?php for ($i=1;$i<count($result['Items']);$i++) { ?>
                     <tr>
                         <td style="width: 150px; vertical-align: top"><strong>
                     <?php echo $result['Items'][$i]['Label']; ?>:
                       </strong></td>
                       <td>
                     <?php if($result['Items'][$i]['Label']=='URL'){ ?>
                           <?php echo $result['Items'][$i]['Data'] ?>
                     <?php }else{ ?>
                     <?php echo $result['Items'][$i]['Data']; ?>
                       </td>
                       <?php } ?>
                     </tr>
                     <?php } ?>
        <?php } ?>

 <!-- PubType -->
        <?php if(!empty($result['pubType'])){ ?>
                     <tr>
                         <td><strong>PubType</strong></td>
                         <td><?php echo $result['pubType'] ?></td>
                     </tr>
        <?php } ?>

 <!-- Database long name -->
        <?php if (!empty($result['DbLabel'])) { ?>
            <tr>
                <td><strong>
                    Database:
            </strong></td>
                <td>
                    <?php echo $result['DbLabel']; ?>
                </td>
            </tr>
        <?php } ?>
        </table>
         <?php if(!empty($result['htmllink'])){?>
         <div id="html" style="margin-top:30px">
             <?php echo $result['htmllink'] ?>
         </div>
         <?php } ?>
         </div>
             <div class="jacket">
                <?php if(!empty($result['ImageInfo'])) { ?>
                 <img width="150px" height="200px" src="<?php echo $result['ImageInfo']['medium']; ?>" />
        <?php } ?>
             </div>
        </div>

         </div>
</div>
 <?php } ?>
    </body>
</html>
