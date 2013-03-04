<?php
class sspmod_wstrust_Auth_Source_MyAuth extends sspmod_core_Auth_UserPassBase {

  protected function login($username, $password) {
    $credentials = get_credentials($username, $password);
    error_log("login called for: $username");
    error_log(var_export($credentials, true));
    if (! ($credentials)) {
      throw new SimpleSAML_Error_Error('WRONGUSERPASS');
    }
    
    return $credentials;
  }
 

}

function get_credentials($username, $password) {
   
  require("wstrustconfig.php");
   
  define('XML_POST_URL', $serviceEndPoint);

  date_default_timezone_set('Europe/London');

  $soap_header='<soapenv:Header>
      <wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
         <wsu:Timestamp wsu:Id="Timestamp-4" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <wsu:Created>%s</wsu:Created>
            <wsu:Expires>%s</wsu:Expires>
         </wsu:Timestamp>
         <wsse:UsernameToken wsu:Id="UsernameToken-3" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <wsse:Username>%s</wsse:Username>
            <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">%s</wsse:Password>
            <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%s</wsse:Nonce>
            <wsu:Created>%s</wsu:Created>
         </wsse:UsernameToken>
      </wsse:Security>
   </soapenv:Header>';

  $soap_body='<soapenv:Body>      
      <wst:RequestSecurityToken xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">            
         <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>            
         <wst:Lifetime>               
            <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2011-09-05T10:49:21.985Z</wsu:Created> 
            <wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2011-09-05T10:54:21.985Z</wsu:Expires> 
         </wst:Lifetime>            
         <wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1</wst:TokenType>            
         <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey</wst:KeyType>            
         <wst:KeySize>256</wst:KeySize>            
         <wst:Entropy>               
            <wst:BinarySecret Type="http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce">QW05fV4gUSy1vkYerIaQ3RUM+eiPi8s4</wst:BinarySecret>            
         </wst:Entropy>            
         <wst:ComputedKeyAlgorithm>http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1</wst:ComputedKeyAlgorithm>         
      </wst:RequestSecurityToken>   
   </soapenv:Body> </soapenv:Envelope>';


  $created= date('Y-m-d') .'T'. date('H:i:s');
  error_log( $created ." ");

  $expires_data = time()+6000;
  $expires= date('Y-m-d',$expires_data) .'T'. date('H:i:s',$expires_data);
  error_log($expires);

  $soap_env='<soapenv:Envelope xmlns:ns="http://docs.oasis-open.org/ws-sx/ws-trust/200512" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">';

  $nonce_base = $username. $password . time() ;

  $nonce = md5($nonce_base);

  $nonce = base64_encode($nonce);

  $soap_header=vsprintf($soap_header,array($created,$expires,$username, $password,$nonce,$created));

  //print $soap_header;


  $soap_request = $soap_env . $soap_header . $soap_body;

  //echo $soap_request;
  $ch = curl_init();

  curl_setopt($ch, CURLOPT_URL, XML_POST_URL); 
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); 
  curl_setopt($ch, CURLOPT_TIMEOUT, 4); 
  curl_setopt($ch, CURLOPT_POSTFIELDS, $soap_request); 
  curl_setopt($ch, CURLOPT_HTTPHEADER, array('Connection: close'));
  curl_setopt($ch, CURLOPT_POST, 1); 
  curl_setopt($ch,CURLOPT_HTTPHEADER,array('Content-Type:text/xml;charset=UTF-8','SOAPAction:http://esysbio.org/sts/saml/IssueToken'));


  $result = curl_exec($ch);
  curl_close($ch);

  $start_xml = stripos($result,"<Assertion");
  
     
  $end_xml = strrpos($result,"</wst:RequestedSecurityToken>");

  // avoid xml parsing errors, in case that is a SOAP fault:
  if (! $start_xml) {
    error_log($result);
    return (false);
  }

  // echo 'start xml ' .$start_xml ."\n"; 
  //echo 'end xml ' .$end_xml ."\n"; 

  $new_length = strlen($result) - $end_xml;
  //echo 'new length ' .$new_length ."\n"; 

  $end = $new_length -  $end_xml;

  $result = substr($result,$start_xml,($end_xml-$start_xml));

  //echo $result; 

  $xml = simplexml_load_string($result);

  $xml->registerXPathNamespace('c', 'urn:oasis:names:tc:SAML:1.0:assertion');
      

 

  $result = $xml->xpath("//c:Attribute[@AttributeName='Project_Role']");
  //print $result;

  $role = "";

  while(list( $key, $node) = each($result)) {
    if ($node->AttributeValue->{0} != $projectId) {
      continue ;
    } else {
      $role = sprintf("%s", $node->AttributeValue->{1});
      // echo '> ',$key,' ',$node->AttributeValue->{0},' ',$node->AttributeValue->{1}, "\n";
    
    }
  }
  if (! $role) {
    error_log("Access denied to $username");
    return (false);
  };

  $resultName = $xml->xpath("//c:Attribute[@AttributeName='UserFullName']");
  while(list( $key, $node) = each($resultName)) 
    {
      $fullName = sprintf("%s", $node->AttributeValue->{0});
    };
  $resultEmail = $xml->xpath("//c:Attribute[@AttributeName='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress']");
  while(list( $key, $node) = each($resultEmail)) 
    {
      $email = sprintf("%s", $node->AttributeValue->{0});
    };
  error_log( "validated user: $username, $fullName, $email, $role \n");

  return array(
		'uid' => array($username),
		'displayName' => array($fullName),
		'role' => array($role),
	        'mail' => array($email),
	        'eduPersonAffiliation' => array('member')
		);



}








 














?>
