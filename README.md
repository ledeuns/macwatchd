```
#doas ./macwatchd -t test

# pfctl -t test -T show                                                       
# echo "a 192.168.10.10" > /var/run/macwatchd.sock                            
# pfctl -t test -T show                                                       
   192.168.10.10
   2001:db8:1::10
   2001:db8:1::11
   fe80:2::847:22a1:7715:f0a0
# echo "d 2001:db8:0001:0000:0000:0000:0000:0010" > /var/run/macwatchd.sock  
# pfctl -t test -T show                                                       
#
```

working but still needs some love (process separation, control program,
etc...)
