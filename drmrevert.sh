#!/bin/bash

cat $1 | while read myline
do
	commitmsg=`echo $myline | awk '{print $1}'`
	git revert -s --no-edit $commitmsg
        if [ $? -eq 0 ]
        then
                echo "ok"
        else
		echo "$myline failed"
                exit -1
        fi
done

