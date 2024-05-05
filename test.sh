#!/bin/bash

# URL to send requests to
url1="www.fakenews.com"
url2="www.pornhub.com"
url3="www.example.com"
url4="foo.com"
url5="chat.openai.com"
url6="github.com"

# Files to store proxy output
proxy_output1="proxy_output1.txt"
proxy_output2="proxy_output2.txt"
proxy_output3="proxy_output3.txt"
proxy_output4="proxy_output4.txt"
proxy_output5="proxy_output5.txt"
proxy_output6="proxy_output6.txt"

# Files to store actual curl output
curl_output1="curl_output1.txt"
curl_output2="curl_output2.txt"
curl_output3="curl_output3.txt"
curl_output4="curl_output4.txt"
curl_output5="curl_output5.txt"
curl_output6="curl_output6.txt"

# Send requests to proxy and pipe output to respective files
curl -x 127.0.0.1:9094 -I $url1 > $proxy_output1 &
wait $!
curl -x 127.0.0.1:9094 -I $url2 > $proxy_output2 &
wait $!
curl -x 127.0.0.1:9094 -I $url3 > $proxy_output3 &
wait $!
curl -x 127.0.0.1:9094 -I $url4 > $proxy_output4 &
wait $!
curl -x 127.0.0.1:9094 -I $url5 > $proxy_output5 &
wait $!
curl -x 127.0.0.1:9094 -I $url6 > $proxy_output6
wait

# Send requests using actual curl and pipe output to respective files
curl --http1.1 -I https://$url1 > $curl_output1 &
wait $!
curl --http1.1 -I https://$url2 > $curl_output2 &
wait $!
curl --http1.1 -I https://$url3 > $curl_output3 &
wait $!
curl --http1.1 -I https://$url4 > $curl_output4 &
wait $!
curl --http1.1 -I https://$url5 > $curl_output5 &
wait $!
curl --http1.1 -I https://$url6 > $curl_output6 
wait

# Compare proxy output with actual curl output
if diff -q $proxy_output1 $curl_output1 >/dev/null; then
    echo "SUCCESS: $url1"
else
    echo "Difference found: $url1"
fi

if diff -q $proxy_output2 $curl_output2 >/dev/null; then
    echo "SUCCESS: $url2"
else
    echo "Difference found: $url2"
fi

if diff -q $proxy_output3 $curl_output3 >/dev/null; then
    echo "SUCCESS: $url3"
else
    echo "Difference found: $url3"
fi

if diff -q $proxy_output4 $curl_output4 >/dev/null; then
    echo "SUCCESS: $url4"
else
    echo "Difference found: $url4"
fi

if diff -q $proxy_output5 $curl_output5 >/dev/null; then
    echo "SUCCESS: $url5"
else
    echo "Difference found: $url5"
fi

if diff -q $proxy_output6 $curl_output6 >/dev/null; then
    echo "SUCCESS: $url6"
else
    echo "Difference found: $url6"
fi

# Optionally, you may want to remove the output files after comparison
# rm $proxy_output1 $proxy_output2 $proxy_output3 $proxy_output4 $proxy_output5 $proxy_output6
# rm $curl_output1 $curl_output2 $curl_output3 $curl_output4 $curl_output5 $curl_output6
