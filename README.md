# TDTP(Trivial Data Transfer Protocol)

TCP 및 UDP를 이용하여 간단한 데이터 통신을 위한 서버/클라이언트

신뢰성이 중요한 데이터는 TCP를 사용\
신뢰성이 중요하지 않고 간단한 데이터는 UDP 사용

빌드 환경
 - Ubuntu 20.04.2 LTS
 - gcc version 9.3.0

빌드 의존성
 - apt-get install libssl-dev

빌드 방법
 - make htb_init : hash table header
 - make server : tdtpd (server daemon)
 - make client : tdtp_client (client program)
 - make all : htb_init + server + client
 - make clean : clean

기본 설정
 - Port : 52625
 - Directory : /tmp/tdtp (server daemon 동작시 자동 생성)
