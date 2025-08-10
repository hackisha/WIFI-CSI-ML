##
sudo ifconfig wlan0 up

## base64 파라미터 생성
mcp -c 2/20 -C 1 -N 1   -m e0:5a:1b:a0:e7:0c,ec:e3:34:21:a5:20,38:18:2b:2e:ef:40

sudo nexutil -Iwlan0 -s500 -b -l34 -v l34 -v AhABEQAAAwDgWhug5wzs4zQhpSA4GCsu70AAAAAAAAAAAA==
