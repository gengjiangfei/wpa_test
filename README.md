# wpa_test


handshake 守护进程等待监听expol帧，并执行四次握手
wpa 辅助命令，完成前期的auth、assoc，和deauth功能

操作步骤：
 一、连接AP
	1、handshake ath8 &
	2、wpa -i ath8 -o auth
	
二、断开AP
    wpa -i ath8 -o deauth