#!/bin/bash
export LC_ALL=C
make || exit 1
while [ 1 ];
	  do
min=1
max=10
DIGIT_LEN=`jot -r 1 $min $max`
STRING=`cat /dev/urandom | head -c $DIGIT_LEN`
LEN=`echo -n "$STRING" | wc -c`
LAST_STRING_FILENAME=last_string.txt
echo -n "$STRING" > $LAST_STRING_FILENAME
MY_HASH="`./ft_ssl_md5 "$STRING"`" && MD5_HASH="`echo "$STRING" | md5 -q`" &&
	if [ "$MY_HASH" = "$MD5_HASH" ];
	then
		echo "string_len = $LEN"
	else
#		echo "string_len = $LEN"
#		./ft_ssl_md5 "$STRING"
		echo  '\n' "$MY_HASH" '\n' "true_hash ->$MD5_HASH" '\n' \
		#		`echo "$STRING" | hexdump` ;
		./ft_ssl_md5 "$STRING" > diff.txt
		./a.out "$STRING" > diff_bin.txt
		diff *diff*
		echo FAILURE; exit 1;
	fi;
done;
