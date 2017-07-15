<?php
/*
	ÖSYM Sınav Sonuçlarını Çeken PHP Kodu 
	
	Hazırlayanlar : 
		Yrd. Doç. Dr. Hüseyin GÜNEŞ (Balıkesir Üniversitesi Mekatronik Mühendisliği)
		Uzm. Özlem TÜLEK (Balıkesir Üniversitesi Bilgi İşlem Daire Başkanlığı)	
*/
	header('Content-type: text/html; charset=utf-8');
	error_reporting(E_ALL);
	ini_set('display_errors', '1');
	
	$kullanici_adi = "*******"; // ÖSYM'den alınan kullanıcı adı
	$sifre = "********"; // ÖSYM'den alınan şifre 
	
	$istemci = new SoapClient("https://".$kullanici_adi.":".$sifre."@vps.osym.gov.tr/Ext/Provider/BilgiServisi/Sonuc?wsdl"); 
	$istemci->__setSoapHeaders(soapClientWSSecurityHeader($kullanici_adi, $sifre));
	
	$servisteki_fonksiyonlar = $istemci->__getFunctions(); // SOAP servisinden çağırabileceğiniz fonksiyonları döndürür.
	var_dump($servisteki_fonksiyonlar);

	echo "<hr>";
	
	$sonuc = $istemci->SinavGrupBilgileriniGetir(); // Sınavların kodlarını döndüren fonksiyon.
	var_dump($sonuc); // burda dönen değeri ekrana yazdırıyoruz.
	echo "<hr>";
	$sinav_kodlari = $sonuc->SinavGrupBilgileriniGetirResult->Sonuc->SinavGrupBilgi; // Bu kısmı da sadece sınav grup bilgilerinin nasıl okunacağını göstermek için ekledim.
	var_dump($sinav_kodlari);
	echo "<hr>";
	
	
	$degiskenler = array("adayTcKimlikNo"=>"*********", "yil"=>2016, "sinavGrupId"=>15); // 15 YDS sınavını ifade ediyor
		// sınav sonucu sorgulanacak kişinin tc'si ile, sınava girdiği yıl ve sınavın üstte çektiğimiz kodu parametre olarak giriliyor.
	
	$sinav_sonuc = $istemci->SinavSonuclariGetir($degiskenler); //yukarıda bilgileri girilen kişinin sınav sonucu çekiliyor.
	var_dump($sinav_sonuc);
	echo "<hr>";
	
	var_dump($sinav_sonuc->SinavSonuclariGetirResult->Sonuc->SinavSonucTemelBilgi); //eğer yılda iki kere yapılan bir sınav ise ilki bahar ikincisi ise güz dönemi sınavı oluyor. (tabi ikisine de girilmişse)
	echo $sinav_sonuc->SinavSonuclariGetirResult->Sonuc->SinavSonucTemelBilgi[0]->Id; // ilk sınavın kodu. foreach ile diğer sınavlarda sırasıyla görülebilir. Yada 0 değeri artırılabilir.
	echo "<hr>";
	
	$degiskenler_2 = array("adayTcKimlikNo"=>"**********", "sonucId"=>4139); // kişinin tc'si ile yukarıda çekilmiş kişinin girdiği sınavın id si
	$sinav_sonuc_html = $istemci->SinavSonucHtml($degiskenler_2); // sınav sonucu html biçiminde
	$sinav_sonuc_xml = $istemci->SinavSonucXml($degiskenler_2); // sınav sonucu xml biçiminde
	var_dump($sinav_sonuc_xml);
	echo "<hr>";
	
	//Sınavın ayrıntılarına erişmek için aşağıdaki örnek satır değiştirilerek kullanılabilir.
	$xml_ayristirilmis = simplexml_load_string($sinav_sonuc_xml->SinavSonucXmlResult->Sonuc->Xml);
	print_r($xml_ayristirilmis);
	echo "<hr>";
	echo $xml_ayristirilmis->TCK; // kişinin TC numarasını yazdırır. Yukarıdaki print_r ile yazdırılan kısımda köşeli parantezler içinde yazılan değerler burada -> işaretinden sonra yazılarak o değerler ayrı ayrı okunabilir.
	//birkaç örnek
	echo "<hr>";
	echo $xml_ayristirilmis->AD;	echo "<hr>";
	echo $xml_ayristirilmis->SOY;	echo "<hr>";
	echo $xml_ayristirilmis->DSAYISI;	echo "<hr>";
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// SOAP headerlarını değiştiren fonksiyon
	function soapClientWSSecurityHeader($user, $password)
	{
		// Creating date using yyyy-mm-ddThh:mm:ssZ format
		$tm_created = gmdate('Y-m-d\TH:i:s\Z');
		$tm_expires = gmdate('Y-m-d\TH:i:s\Z', gmdate('U') + 180); //only necessary if using the timestamp element
		
		// Generating and encoding a random number
		$simple_nonce = mt_rand();
		$encoded_nonce = base64_encode($simple_nonce);
		
		// Compiling WSS string
		$passdigest = base64_encode(sha1($simple_nonce . $tm_created . $password, true));
		
		// Initializing namespaces
		$ns_wsse = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
		$ns_wsu = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
		$password_type = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText';
		$encoding_type = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';
		
		// Creating WSS identification header using SimpleXML
		$root = new SimpleXMLElement('<root/>');
		
		$security = $root->addChild('wsse:Security', null, $ns_wsse);
		
		//the timestamp element is not required by all servers
		$timestamp = $security->addChild('wsu:Timestamp', null, $ns_wsu);
		$timestamp->addAttribute('wsu:Id', 'Timestamp-28');
		$timestamp->addChild('wsu:Created', $tm_created, $ns_wsu);
		$timestamp->addChild('wsu:Expires', $tm_expires, $ns_wsu);
		
		$usernameToken = $security->addChild('wsse:UsernameToken', null, $ns_wsse);
		$usernameToken->addChild('wsse:Username', $user, $ns_wsse);
		$usernameToken->addChild('wsse:Password', $password, $ns_wsse)->addAttribute('Type', $password_type);
		//$usernameToken->addChild('wsse:Nonce', $encoded_nonce, $ns_wsse)->addAttribute('EncodingType', $encoding_type);
		//$usernameToken->addChild('wsu:Created', $tm_created, $ns_wsu);
		
		// Recovering XML value from that object
		$root->registerXPathNamespace('wsse', $ns_wsse);
		$full = $root->xpath('/root/wsse:Security');
		$auth = $full[0]->asXML();
		
		return new SoapHeader($ns_wsse, 'Security', new SoapVar($auth, XSD_ANYXML), true);
   }
?>