#!/bin/bash
#
# To be run from cron as root:
# */2 * * * *     root PATH_TO_SCRIPT/blockSshByIP.sh  
# Set this variable for the number of failed attempts from an ip

myName=$(basename $0 .sh)
mailBody=$(mktemp /tmp/$myName.mailBody.XXXXXX)
mailLine=$(mktemp /tmp/$myName.mailLine.XXXXXX)
globalIgnore="79.99.3.198 130.237.168.229 92.244.30.210 130.237.95.227"
date=$(date +'%Y-%m-%dT%H:%M:%S')

# Debug function
db() {
	if [ X"$debug" != X"" ];then
		echo $*
	fi
}
 
# Source conffile if exists, else use defaults
if [ ! -f /etc/${myName}.conf ]; then
	db "/etc/${myName}.conf dose not exists, write default conf"
cat << EOF > /etc/${myName}.conf 
mailto=""
saveFile="/var/${myName}.save"
ignoreFile="/var/${myName}.ignore"
maxAttempts="3"
logfile="/var/log/auth.log"
EOF
	if [ $? -ne "0" ]; then
		echo "Could not write /etc/${myName}.conf"
		exit 1
	fi
fi

source /etc/${myName}.conf


# block ip, read lines with number of attempts and ipadress. Also takes argumenst of comment.
blockIp() {
	while read line
	do
		db "blockIp() was called with: argument: $* line: $line"
		attempts=$(echo $line | awk '{print $1}')
		ip=$(echo $line | awk '{print $2}')
		MESS="$*"

		# Check if $ip is an ip
		echo $ip | egrep -q '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
	        if [ $? -eq 0 ]; then
			db "$ip is an ip"
		else
			db "$ip is not an ip"
			ip=$(host $ip | awk '{print $4}' | egrep -o '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
			db "Done hosting, ip: $ip"
			if [ "$ip" = "found:" ]; then
				echo "Could not host ip from: $line"
				continue
			fi
			if [ X"$ip" = X"" ]; then
				echo "Could not host $IP, is empty. From: $line"
				continue
			fi
		fi
		

		db "Check global ignorelist"
		echo $globalIgnore | grep -q $ip
	        if [ $? -eq 0 ]; then
			db "Found $ip in global ignorelist"
			continue
		else
			db "$IP not in global ignorelist"
		fi
		
		db "Check local ignorefile"
		if [ -f $ignoreFile ];then
			grep -q $ip $ignoreFile 
	        	if [ $? -eq 0 ]; then
				db "Found $ip in local ignoreFile"
				continue
		else
				db "$IP not in local ignorefile"
			fi
		else
			db "No local ignorefile"
		fi 

		if [ $attempts -ge $maxAttempts ]; then
	        	db "Check if $ip is already blocked..."
		        /sbin/iptables -L -n | grep -q " $ip "
		        if [ $? -eq 0 ]; then
		                db "Already denied ip: [$ip]"
		        else
				db "Blocking $ip"
		                logger -p authpriv.notice "*** Blocked SSH attempt from: $ip"
		                cmd="/sbin/iptables -A INPUT -s $ip -p tcp --dport 22 -j DROP"
				if [ ! -z $saveFile ]; then
					echo "$cmd # $date  $MESS">> $saveFile
				fi
				if [ ! -z $mailto ]; then
					echo "$cmd # $date  $MESS">> $mailBody
				fi
				eval $cmd
		        fi
		fi
	done
}



db "grep 1"
grep 'Invalid user' $logfile | awk '{print $10}' |sort | uniq -c | blockIp "Invalid user"

db "grep 2"
grep 'Failed password for invalid user' $logfile | awk '{print $13}' |sort | uniq -c | blockIp "Failed password for"

db "grep 3"
grep 'Failed password for' $logfile | grep -v 'invalid' |awk '{print $11}' |sort | uniq -c | blockIp "Failed password for valid user"

db "grep 4"
grep 'not listed in AllowUsers' $logfile | awk '{print $9}' |sort | uniq -c | blockIp "Not listed in AllowUsers"

db "grep 5"
grep 'reverse mapping checking getaddrinfo for' $logfile |  awk -F '[' '{print $3}' |awk -F ']' '{print $1}' |sort | uniq -c | blockIp "Reverse mapping checking getaddrinfo"

if [ ! -z $mailto ];then
	if [ $(wc -l $mailBody | awk '{print $1}') -gt 0 ];then
		cat $mailBody | mail -s "$myName newly blocked addresses" $mailto
	fi
fi

if [ -f $mailBody ];then
	rm $mailBody
fi
if [ -f $mailLine ];then
	rm $mailLine
fi
