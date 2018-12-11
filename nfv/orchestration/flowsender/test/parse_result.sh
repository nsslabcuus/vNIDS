#!/bin/bash

files=$(ls -l *_update_sw.time.dat | awk '{print $9}' | sort -n)

echo "rules,  average(ms),  variance"
for f in $files; do
    fname=`echo $f | cut -d '_' -f1`
    echo "$fname,"`awk -F ',' 'BEGIN{sum=0;summ=0}{sum+=$2;summ+=$2*$2}END{avg=sum/NR;avg2=summ/NR;printf("%f,%f",avg,sqrt(avg2-avg*avg))}' $f`
done
