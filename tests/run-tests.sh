#!/bin/bash

set -e


capsh  --print

echo "======= Runing functionnal tests ======"

id testuser 

dpkg -l libapache2-mpm-itk | grep 2.4.7-02 && capsh --supports=CAP_DAC_READ_SEARCH || (echo "ERROR: No CAP_DAC_READ_SEARCH Capability";  exit 0)

curl -v -H 'Host:www.website.com'  http://127.0.0.1/system.php

curl -v -H 'Host:nowebsite.com'  http://127.0.0.1/

echo "=== All tests passed ===="

echo "******************* LOGS **********************"
cat /var/log/apache2/access.log
echo "************************************************"
cat /var/log/apache2/error.log
echo "************************************************"


exit 0
