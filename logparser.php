<?php
header('Content-type: text/html; charset=utf-8');
$start_time = microtime(true);

error_reporting(E_ALL);
ini_set('display_errors', 1);

define('EOL', "<br/>");
define('DEMO_LOGPATH', "demo_log.0");
define('TEST_LOGPATH', " " );

$logpath = DEMO_LOGPATH;

//White list - friendly POST-requests, e.g. any normal repeating external activation some site services
$whitelist = array( //This is only examples - please, change white list on your normal POST requests
	"http://samurai.spb.ru/post.php",
	"http://samurai.spb.ru/mobile/post.php",
	);

echo "<h1>Apache Log parser Script for analyze suspicious POST-requests</h1>";

echo "<b>Path to analyzed log file: </b>" . $logpath;

ob_start(); //Output buffering for acceleration ~2 times
echo "<b>POST requests from log for the date: </b>". date("F d Y", filemtime($logpath) - 24*3600) . EOL;

//Ideally, 1 day should be subtracted, if the log time is 0:00. Those. when the rotation worked just right.

$result = array();
$request_count = 0;
$post_count = 0;
$post404_count = 0;
$read = fopen($logpath, "r");

if ($read)
{
	while (!feof($read))
	{
		$logstr = fgets($read, 999);
	
		if (strpos($logstr, '"POST ')) //May be use regular expressions?
		{
			$matches = array();
			$regex = "/\"POST (?P<req_link>\S+)\"(?P<code>\s\d{3}\s)(?P<bytes>\d+\s)/";
			
			preg_match($regex, $logstr, $matches);
	
			if (isset($matches['req_link']))
			{
				if (!in_array($matches['req_link'], $whitelist))//If the link does not belong to the white list... white list using for known POST-requests which are guaranteed not viruses-requests
				{ 
				  if ($matches['code'] != 404)
				  {
					$print = urldecode($matches['req_link']); //%D0 has gone!
					
					$result[$post_count]['req_link'] = $print;
					$result[$post_count]['code'] = $matches['code'];
					$result[$post_count]['bytes'] = $matches['bytes'];
					$post_count++;
				  } else
					  $post404_count++;
				}
			} else
				echo "<b>Suspected: $logstr</b>".EOL;
		}
		$request_count++;
		//if ($i > 10000) break; //For stop
	}
	
	echo "<b>Number of requests in the log file:</b> $request_count"."<br/>";
	echo "<b>Number of suspected POST requests:</b> $post_count (except 404 codes - their $post404_count)".EOL.EOL;
	/* Разделить всё что не 404-е от остального */
}
else die("Error opening file: " . $logpath);

fclose($read);

$result = array_count_values(array_map("serialize", $result)); //Request data => number of repetitions

$buf = array();

foreach ($result as $item => $number)
{
	$data = unserialize($item);
	$data['repeat_count'] = $number;
	$buf[] = $data;
}

function sort_by_rcount($a, $b)
{
	if ($a['repeat_count'] == $b['repeat_count'])
		return 0;
	return ($a['repeat_count'] > $b['repeat_count']) ? -1 : 1;
}

usort($buf, "sort_by_rcount");

/* Analyze 302 Redirects which followed by POST-requests */
$buf302 = array();

foreach ($buf as $item)
{
	$print_str = $item['req_link']." | Response code ".$item['code']." | Bytes: ". $item['bytes'];
	$number = $item['repeat_count'];
    if ($number > 1) $print_str .= " (<b>was send $number time(s)</b>)";
	if ($item['code'] == 302)
		$buf302[] = $print_str;
	else
		echo "$print_str".EOL;
}

echo EOL. "<b><u>302 Redirects - possibly, the hacker was sent fucked</u></b>".EOL;

foreach ($buf302 as $string)
{
	echo "$string".EOL;
}

$main_content = ob_get_clean();

$delta_time = microtime(true) - $start_time;
echo "<br/><b>Script execution time:</b> ".$delta_time." s"."<br/><br/>";

echo $main_content; //Output big data

/*  -------------- GTD -------   */
/*  List of projected additions  */
/*  
/*  1. Cosmetic CSS styles...
/*
/*
/*
/* --------------------------  */