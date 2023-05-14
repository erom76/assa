#!/bin/sh

LANG=C
export LANG

alias ls=ls

BUILD_VER=1.2.1
LAST_UPDATE=2015.03.19
CREATE_FILE=`hostname`"_before_ini_".txt

#
# LINUX Vulnerability Scanner
# 

echo " " >> $CREATE_FILE 2>&1
echo "###################################################################" >> $CREATE_FILE 2>&1
echo "     LINUX Vulnerability Check Version $BUILD_VER ($LAST_UPDATE)   " >> $CREATE_FILE 2>&1
echo "###################################################################" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "INFO_CHKSTART"  >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1

echo "###################################   Linux Security Check Ver $BUILD_VER ($LAST_UPDATE)   ######################################"
echo "###################################   Linux Security Check Ver $BUILD_VER ($LAST_UPDATE)   ######################################" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "############################################ Start Time ################################################"
date
date +%y%m > dtmp
echo " "
echo "############################################ Start Time ################################################" >> $CREATE_FILE 2>&1
date >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "=================================== System Information Query Start ====================================="
echo "=================================== System Information Query Start =====================================" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "#######################################   Kernel Information   #########################################"
echo "#######################################   Kernel Information   #########################################" >> $CREATE_FILE 2>&1
uname -a >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "#########################################   IP Information   ###########################################"
echo "#########################################   IP Information   ###########################################" >> $CREATE_FILE 2>&1
ifconfig -a >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "#########################################   Network Status   ###########################################"
echo "#########################################   Network Status   ###########################################" >> $CREATE_FILE 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "#######################################   Routing Information   ########################################"
echo "#######################################   Routing Information   ########################################" >> $CREATE_FILE 2>&1
netstat -rn >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "##########################################   Process Status   ##########################################"
echo "##########################################   Process Status   ##########################################" >> $CREATE_FILE 2>&1
ps -ef >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "-----------------------------------------   SSHD config   -----------------------------------------------"
echo "-----------------------------------------   SSHD config   -----------------------------------------------" >> $CREATE_FILE 2>&1
cat /etc/ssh/sshd_config | grep sftp >> $CREATE_FILE 2>&1
cat /etc/ssh/sshd_config | grep Banner >> $CREATE_FILE 2>&1
cat /etc/ssh/sshd_config | grep Banner | grep -v '#' | awk -F" " '{print $2}' > sshd_temp
if [ `cat sshd_temp | wc -l` -gt 0 ]
  then
    sshbanner=`cat sshd_temp`
    if [ -f $sshbanner ]
      then
        cat $sshbanner >> $CREATE_FILE 2>&1
      else
        echo "배너 파일 없음" >> $CREATE_FILE 2>&1
    fi
  else
    echo "배너설정 없음" >> $CREATE_FILE 2>&1
fi
rm -rf sshd_temp
echo " " >> $CREATE_FILE 2>&1
echo "-----------------------------------------   FTP config   -----------------------------------------------"
echo "-----------------------------------------   VSFTPD config   -----------------------------------------------" >> $CREATE_FILE 2>&1
ps -ef | grep vsftpd >> $CREATE_FILE 2>&1
if [ -f /etc/vsftpd/vsftpd.conf ]
  then
    echo "[vsftpd.conf]" >> $CREATE_FILE 2>&1
    cat /etc/vsftpd/vsftpd.conf | grep -v '#' >> $CREATE_FILE 2>&1
  else
    echo "/etc/vsftpd/vsftpd.conf 파일 없음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/vsftpd/ftpusers ]
  then
    echo "[ftpusers]" >> $CREATE_FILE 2>&1
    cat /etc/vsftpd/ftpusers >> $CREATE_FILE 2>&1
  else
    echo "/etc/vsftpd/ftpusers 파일 없음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/vsftpd/user_list ]
  then
    echo "[user_list]" >> $CREATE_FILE 2>&1
    cat /etc/vsftpd/user_list >> $CREATE_FILE 2>&1
  else
    echo "/etc/vsftpd/user_list 파일 없음" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
echo "-----------------------------------------   PROFTPD config   -----------------------------------------------" >> $CREATE_FILE 2>&1
echo " [ ProFTPD 프로세스 ]" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep proftp | grep -v "grep" | wc -l` -gt 0 ]
  then
    echo " # proftpd : running ..." >> $CREATE_FILE 2>&1
    ps -ef | grep proftp | grep -v "grep" >> $CREATE_FILE 2>&1
    echo " " >> $CREATE_FILE 2>&1
    find /etc/ -name "proftpd.conf" >> proftpd_etc.log
    find /usr/local/ -name "proftpd.conf" >> proftpd_usr.log

    if [ `cat proftpd_etc.log | wc -l` -gt 0 ]
      then
        pftpd_conf=`cat proftpd_etc.log`
	if [ -f $pftpd_conf ]
	  then
	    echo "["$pftpd_conf"]" >> $CREATE_FILE 2>&1
	    cat $pftpd_conf >> $CREATE_FILE 2>&1
	  else
	    echo $pftpd_conf" file not found" >> $CREATE_FILE 2>&1
	fi
      else
        if [ `cat proftpd_usr.log | wc -l` -gt 0 ]
	  then
	    pftpd_conf=`cat proftpd_usr.log`
	    if [ -f $pftpd_conf ]
	      then
	        echo "["$pftpd_conf"]" >> $CREATE_FILE 2>&1
		cat $pftpd_conf >> $CREATE_FILE 2>&1
	      else
	        echo $pftpd_conf" file not found" >> $CREATE_FILE 2>&1
	    fi
	  else
	    echo "proftpd.conf file not found" >> $CREATE_FILE 2>&1
	fi
    fi

    rm -rf proftpd_etc.log
    rm -rf proftpd_usr.log
  else
    echo " # proftpd : not running ..." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "##########################################   User Env   ################################################"
echo "##########################################   User Env   ################################################" >> $CREATE_FILE 2>&1
env >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1

echo "##########################################  lsof -i -P  ################################################"
echo "##########################################  lsof -i -P  ################################################" >> $CREATE_FILE 2>&1
lsof -i -P >> $CREATE_FILE 2>&1
lsof -i -P > `hostname`_lsof.txt
echo " " >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1

echo "=================================== System Information Query End ======================================="
echo "=================================== System Information Query End =======================================" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1
echo "INFO_CHKEND"  >> $CREATE_FILE 2>&1

if [ `cat dtmp | awk '$1 > "2002" {print $1}' | wc -l` -eq 1 ]
  then
    echo " " >> $CREATE_FILE 2>&1
  else
#    CREATE_FILE=`hostname`_result_temp2.txt
    echo " "
    echo " ##  스크립트 사용기간이 만료되었습니다 !"
    echo " ##  아래의 연락처로 문의해주시기 바랍니다."
    echo " ##  This script period has expired !"
    echo " ##  Please contact us below."
    echo " ##  - Contact : jwkim@sgsecurity.co.kr"
    echo " "
    echo " " >> $CREATE_FILE 2>&1
    echo " ##  스크립트 사용기간이 만료되었습니다 !" >> $CREATE_FILE 2>&1
    echo " ##  아래의 연락처로 문의해주시기 바랍니다." >> $CREATE_FILE 2>&1
    echo " ##  This script period has expired !" >> $CREATE_FILE 2>&1
    echo " ##  Please contact us below." >> $CREATE_FILE 2>&1
    echo " ##  - Contact : jwkim@sgsecurity.co.kr" >> $CREATE_FILE 2>&1
    echo " " >> $CREATE_FILE 2>&1

    rm -rf dtmp
    rm -rf `hostname`_lsof.txt
    mv `hostname`"_before_ini_.txt" "LINUX_"`hostname`"_"`date +%m%d`"-"`date +%H%M`.txt
    exit
fi

echo >> $CREATE_FILE 2>&1
echo "********************************************* START ****************************************************" >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1
echo
echo "********************************************* START ****************************************************"
echo
echo >> $CREATE_FILE 2>&1

echo "1.01 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.01. Default 계정 삭제 ########################################"
echo "############################ 1.계정관리 - 1.01. Default 계정 삭제 ########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/passwd파일에 lp, uucp, nuucp 계정이 모두 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | grep -v "^#" | egrep "lp|uucp|nuucp" | wc -l` -eq 0 ]
  then
    echo "lp, uucp, nuucp 계정이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
  else
    cat /etc/passwd | grep -v "^#" | egrep "lp|uucp|nuucp" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


if [ `cat /etc/passwd | grep -v "^#" | egrep -i "lp|uucp|nuucp" | grep -v "lpd" | wc -l` -gt 0 ]
    then
      echo "● 1.01 결과 : 취약" >> $CREATE_FILE 2>&1
    else
      echo "● 1.01 결과 : 양호" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "1.02 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.02. root 권한 관리 ##########################################"
echo "############################ 1.계정관리 - 1.02. root 권한 관리 ##########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : root 계정만이 UID가 0이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo "☞ /etc/passwd 파일 내용" >> $CREATE_FILE 2>&1
cat /etc/passwd >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `awk -F: '$3==0  { print $1 }' /etc/passwd | grep -v "root" | wc -l` -eq 0 ]
  then
    echo "● 1.02 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 1.02 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "1.03 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.03. passwd 파일 권한 설정 ####################################"
echo "############################ 1.계정관리 - 1.03. passwd 파일 권한 설정 ####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/passwd 파일의 권한이 444 또는 644이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    ls -alL /etc/passwd >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


if [ `ls -alL /etc/passwd | grep "...-.--.--" | wc -l` -eq 1 ]
  then
    echo "● 1.03 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 1.03 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "1.04 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.04. group 파일 권한 설정 #####################################"
echo "############################ 1.계정관리 - 1.04. group 파일 권한 설정 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/group 파일의 권한이 644이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -alL /etc/group   >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ls -alL /etc/group |  grep "...-.--.--" | awk '{print $3}' | wc -l` -eq 1 ]
      then
        echo "● 1.04 결과 : 양호" >> $CREATE_FILE 2>&1
      else
        echo "● 1.04 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.05 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.05. shadow 파일 권한 설정 ####################################"
echo "############################ 1.계정관리 - 1.05. shadow 파일 권한 설정 ####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/shadow 파일의 권한이 400 또는 600이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
  then
    ls -alL /etc/shadow >> $CREATE_FILE 2>&1
  else
    echo " /etc/shadow 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ `ls -alL /etc/shadow | grep "...-------" | wc -l` -eq 1 ]
  then
    echo "● 1.05 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 1.05 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "1.06 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.06. shell 제한 ###############################################"
echo "############################ 1.계정관리 - 1.06. shell 제한 ###############################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 로그인이 필요하지 않은 시스템 계정에 /bin/false(nologin) 쉘이 부여되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher|^sysmgmt" | grep -v "admin" >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" |  awk -F: '{print $7}'| egrep -v 'false|nologin|null|halt|sync|shutdown' | wc -l` -eq 0 ]
  then
    echo "● 1.06 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 1.06 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.07 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.07. su 제한 ##################################################"
echo "############################ 1.계정관리 - 1.07. su 제한 ##################################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/pam.d/su 파일의 설정이 아래와 같을 경우 양호, 아래설정이 없을 경우 /bin/su 파일 권한이 4750 이면 양호" >> $CREATE_FILE 2>&1
echo "         auth       required   /lib/security/pam_wheel.so debug group=wheel" >> $CREATE_FILE 2>&1
echo "         또는" >> $CREATE_FILE 2>&1
echo "         auth       required     /lib/security/\$ISA/pam_wheel.so use_uid" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/su ]
  then
    echo "① /etc/pam.d/su 파일" >> $CREATE_FILE 2>&1
    cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' >> $CREATE_FILE 2>&1
  else
    echo "/etc/pam.d/su 파일이 없습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo "② /bin/su 파일" >> $CREATE_FILE 2>&1
if [ `ls -al /bin/su | wc -l` -eq 0 ]
 then
   echo "/bin/su 파일이 없습니다. " >> $CREATE_FILE 2>&1
 else
   ls -al /bin/su >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo "③ /etc/group 파일" >> $CREATE_FILE 2>&1
cat /etc/group >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1

if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v '#' | grep -v 'trust' | wc -l` -eq 0 ]
 then
   if [ -f /bin/su ]
   then
     if [ `ls -alL /bin/su | grep ".....-.---" | wc -l` -eq 1 ]
       then
         echo "● 1.07 결과 : 양호" >> $CREATE_FILE 2>&1
       else
         echo "● 1.07 결과 : 취약" >> $CREATE_FILE 2>&1
     fi
   else
    echo "● 1.07 결과 : 취약" >> $CREATE_FILE 2>&1
  fi
 else
   echo "● 1.07 결과 : 양호" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.07 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "1.08 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.08. 패스워드 사용규칙 적용 ##################################"
echo "############################ 1.계정관리 - 1.08. 패스워드 사용규칙 적용 ##################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 패스워드 최소 길이가 8자 이상 (/etc/login.defs, PASS_MIN_LEN 8)" >> $CREATE_FILE 2>&1
#echo "        패스워드 최대 사용기간이 90일 이하 (/etc/login.defs, PASS_MAX_DAYS 90)" >> $CREATE_FILE 2>&1
echo "        패스워드 최소 사용기간이 7일(1주) 이상으로 설정되어 있으면 양호 (/etc/login.defs, PASS_MIN_DAYS 1)" >> $CREATE_FILE 2>&1   
echo "■ 현황" >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/login.defs ]
  then
    cat /etc/login.defs | grep -v '#' | grep -v 'grep' | grep -i "PASS_MIN_LEN" >> $CREATE_FILE 2>&1
#    cat /etc/login.defs | grep -v '#' | grep -v 'grep' | grep -i "PASS_MAX_DAYS" >> $CREATE_FILE 2>&1
    cat /etc/login.defs | grep -v '#' | grep -v 'grep' | grep -i "PASS_MIN_DAYS" >> $CREATE_FILE 2>&1
  else
    echo "/etc/login.defs 파일이 존재하지 않음 " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo " " > result_108.txt

if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "#" | egrep [0-9]| awk '{print $2}'| wc -l` -eq 0 ]
  then
    echo "● 1.08.1 결과 : 취약" >> result_108.txt 2>&1
  else
    if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "#" | awk '{print $2}'` -ge 7 ]
      then
        echo "● 1.08.1 결과 : 양호" >> result_108.txt 2>&1
      else
        echo "● 1.08.1 결과 : 취약" >> result_108.txt 2>&1
    fi
fi

#if [ `cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "#" | egrep  [0-9]| awk  '{print $2}'| wc -l ` -eq 0 ]
# then
#    echo "● 1.08.2 결과 : 취약" >> result_108.txt 2>&1
# else
#   if [ `cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "#" | awk '{print $2}'` -lt 89 ]
#    then
#     echo "● 1.08.2 결과 : 양호" >> result_108.txt 2>&1
#    else
#     echo "● 1.08.2 결과 : 취약" >> result_108.txt 2>&1
#   fi
#fi

if [ `cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | egrep [0-9] | grep -v "#" | awk '{print $2}' | wc -l` -eq 0 ]
 then
   echo "● 1.08.3 결과 : 취약" >> result_108.txt 2>&1
 else
  if [ `cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "#" | awk '{print $2}'` -ge 6 ]
   then
     echo "● 1.08.3 결과 : 양호" >> result_108.txt 2>&1
   else
     echo "● 1.08.3 결과 : 취약" >> result_108.txt 2>&1
  fi
fi

if [ `cat result_108.txt | grep "취약" | grep -v "grep" | wc -l` -gt 0 ]
  then
    echo "● 1.08 결과 : 취약" >> $CREATE_FILE 2>&1
  else
    echo "● 1.08 결과 : 양호" >> $CREATE_FILE 2>&1
fi

rm -rf result_108.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "1.09 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.09. Trivial Password ########################################"
echo "############################ 1.계정관리 - 1.09. Trivial Password ########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 패스워드가 5분동안 크랙되지 않을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    echo "☞ /etc/passwd 파일 " >> $CREATE_FILE 2>&1
    cat /etc/passwd >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/shadow ]
  then
    echo "☞ /etc/shadow 파일 " >> $CREATE_FILE 2>&1
    cat /etc/shadow >> $CREATE_FILE 2>&1
  else
    echo "/etc/shadow 파일이 없습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "● 1.09 결과 : 양호" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.09 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.01 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.01. UMASK 설정 #############################################"
echo "############################ 2.파일시스템 - 2.01. UMASK 설정 #############################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : UMASK 값이 022 또는 027이면 양호 (/etc/profile)" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1

echo "☞ UMASK 명령어  " >> $CREATE_FILE 2>&1
umask >> $CREATE_FILE 2>&1

echo "  " >> $CREATE_FILE 2>&1

echo "☞ /etc/profile 파일  " >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
 then
   cat /etc/profile | grep -i umask >> $CREATE_FILE 2>&1
 else
   echo "/etc/profile 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo "  " >> $CREATE_FILE 2>&1

echo " " > mask.txt

if [ `umask` -ge 22  ]
  then
    echo "● 2.01 결과 : 양호" >> mask.txt
  else
    echo "● 2.01 결과 : 취약" >> mask.txt
fi

if [ `umask` -ge 27  ]
  then
    echo "● 2.01 결과 : 양호" >> mask.txt
  else
    echo "● 2.01 결과 : 취약" >> mask.txt
fi

if [ -f /etc/profile ]
  then
   if [ `cat /etc/profile | grep -i "umask" |grep -v "#" | awk -F"0" '$2 >= "22"' | wc -l` -eq 1 ]
     then
       echo "● 2.01 결과 : 양호" >> mask.txt
     else
       echo "● 2.01 결과 : 취약" >> mask.txt
   fi
  else
   echo "● 2.01 결과 : 양호" >> mask.txt
fi

if [ `cat mask.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.01 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.01 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf mask.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.02 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.02. setuid, setgid 설정 ####################################"
echo "############################ 2.파일시스템 - 2.02. setuid, setgid 설정 ####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 불필요한 setuid, setgid 파일이 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

for check_file in $FILES
  do
    if [ -f $check_file ]
      then
        if [ -g $check_file -o -u $check_file ]
          then
            echo `ls -alL $check_file` >> $CREATE_FILE 2>&1
        else
        :
        fi
      else
        echo $check_file "이 없습니다" >> $CREATE_FILE 2>&1
    fi
done
echo " " >> $CREATE_FILE 2>&1


echo "setuid " > set.txt
FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

for check_file in $FILES
  do
     if [ -f $check_file ]
      then
       if [ `ls -alL $check_file | awk '{print $1}' | grep -i 's'| wc -l` -gt 0 ]
           then
              ls -alL $check_file |awk '{print $1}' | grep -i 's' >> set.txt
           else
              echo " " >> set.txt
       fi
     fi
done

if [ `cat set.txt | awk '{print $1}' | grep -i 's' | wc -l` -gt 1 ]
    then
           echo "● 2.02 결과 : 취약" >> $CREATE_FILE 2>&1
    else
           echo "● 2.02 결과 : 양호" >> $CREATE_FILE 2>&1
fi
rm -rf set.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.03 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.03. inetd.conf 파일권한 설정 ##############################"
echo "############################ 2.파일시스템 - 2.03. inetd.conf 파일권한 설정 ##############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/xinetd.conf 파일 및 /etc/xinetd.d/ 하위 모든 파일이 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d ]
  then
    ls -al /etc/xinetd.d/* >> $CREATE_FILE 2>&1
  else
    echo "/etc/xinetd.d 디렉토리가 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/xinetd.conf ]
  then
    ls -al /etc/xinetd.conf >> $CREATE_FILE 2>&1
  else
    echo " /etc/xinetd.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo " " > inetd.txt

if [ -f /etc/xinetd.conf ]
then
if [ `ls -alL /etc/xinetd.conf | awk '{print $1}' | grep '........-.'| wc -l` -eq 1 ]
  then
    echo "● 2.03 결과 : 양호" >> inetd.txt
  else
    echo "● 2.03 결과 : 취약" >> inetd.txt
fi
else
 echo "● 2.03 결과 : 양호" >> inetd.txt
fi


if [ -d /etc/xinetd.d ]
  then
    if [ `ls -alL /etc/xinetd.d/* | awk '{print $1}' | grep '........w.'| wc -l` -gt 0 ]
      then
        echo "● 2.03 결과 : 취약" >> inetd.txt
      else
        echo "● 2.03 결과 : 양호" >> inetd.txt
    fi
  else
    echo "● 2.03 결과 : 양호" >> inetd.txt
fi

if [ `cat inetd.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.03 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.03 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf inetd.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.04 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.04. .sh_history 파일권한 설정 #############################"
echo "############################ 2.파일시스템 - 2.04. .sh_history 파일권한 설정 #############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : .sh_history, .bash_history 파일 권한이 600 이하이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false'| grep -wv "/"`
FILES=".sh_history .bash_history"

for file in $FILES
  do
    FILE=$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
    fi
  done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    FILE=$dir/$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
    fi
  done
done
echo " " >> $CREATE_FILE 2>&1

echo " " > homesh.txt

HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -wv "/"`
FILES=".sh_history .bash_history"

 for dir in $HOMEDIRS
    do
      for file in $FILES
          do
            if [ -f $dir/$file ]
             then
             if [ `ls -al $dir/$file | grep -wv "\/" | grep "...-------" | wc -l` -eq 1 ]
              then
                echo "● 2.04 결과 : 양호" >> homesh.txt
              else
                echo "● 2.04 결과 : 취약" >> homesh.txt
             fi
            else
              echo "● 2.04 결과 : 양호" >> homesh.txt
            fi
         done
    done

if [ `cat homesh.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.04 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.04 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf homesh.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.05 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.05. Crontab 관련 파일의 접근 제한 #########################"
echo "############################ 2.파일시스템 - 2.05. Crontab 관련 파일의 접근 제한 #########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : Crontab 관련 파일에 타사용자에게 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
cro="/etc/crontab /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* /var/spool/cron/*"

for check_dir in $cro
do
  if [ -f $check_dir ]
    then
      ls -alL $check_dir >> $CREATE_FILE 2>&1
    else
      echo $check_dir " 이 없습니다" >> $CREATE_FILE 2>&1
  fi
done

echo " " >> $CREATE_FILE 2>&1




cro="/etc/crontab /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* /var/spool/cron/*"

echo " " > crontab.txt
for check_dir in $cro
do

  if [  `ls -alL $check_dir | awk '{print $1}' |grep  '........w.' |wc -l` -eq 0 ]
    then
      echo "● 2.05 결과 : 양호" >> crontab.txt
    else
      echo "● 2.05 결과 : 취약" >> crontab.txt
  fi
done

if [ `cat crontab.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.05 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.05 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf crontab.txt


echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1






echo "2.06 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.06. profile 파일권한 설정 #################################"
echo "############################ 2.파일시스템 - 2.06. profile 파일권한 설정 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/profile의 권한이 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
  then
    ls -alL /etc/profile >> $CREATE_FILE 2>&1
  else
    echo " /etc/profile 파일 없음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


if [ -f /etc/profile ]
then
if [ `ls -alL /etc/profile | awk '{print $1}' | grep '........-.'| wc -l` -eq 1 ]
  then
     echo "● 2.06 결과 : 양호" >> $CREATE_FILE 2>&1
  else
     echo "● 2.06 결과 : 취약" >> $CREATE_FILE 2>&1
fi
else
 echo "● 2.06 결과 : 양호" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.07 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.07. hosts 파일권한 설정 ###################################"
echo "############################ 2.파일시스템 - 2.07. hosts 파일권한 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/hosts의 권한이 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/hosts ]
  then
    ls -alL /etc/hosts >> $CREATE_FILE 2>&1
   else
    echo "/etc/hosts 파일 없음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1



if [ -f /etc/hosts ]
then
if [ `ls -alL /etc/hosts | awk '{print $1}' | grep '........-.'| wc -l` -eq 1 ]
  then
    echo "● 2.07 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 2.07 결과 : 취약" >> $CREATE_FILE 2>&1
fi
else
 echo "● 2.07 결과 : 양호" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.07 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.08 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.08. issue 파일권한 설정 ##################################"
echo "############################ 2.파일시스템 - 2.08. issue 파일권한 설정 ##################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/issue이 소유자가 root 또는 bin이면서 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/issue ]
  then
    ls -alL /etc/issue >> $CREATE_FILE 2>&1   
   else    
    echo "/etc/issue 파일 없음" >> $CREATE_FILE 2>&1    
fi
echo " " >> $CREATE_FILE 2>&1



if [ -f /etc/issue ]
then
if [ `ls -alL /etc/issue | grep '........-.'| awk '{print $3}' | egrep "root|bin" |wc -l` -eq 1 ]
  then
    echo "● 2.08 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 2.08 결과 : 취약" >> $CREATE_FILE 2>&1
fi
else
 echo "● 2.08 결과 : 양호" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.09 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.09. 홈 디렉터리 권한 설정 ##################################"
echo "############################ 2.파일시스템 - 2.09. 홈 디렉터리 권한 설정 ##################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 홈 디렉터리에(/home) 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
         for dir in $HOMEDIRS
          do
            ls -dal $dir | grep '\d.........' >> $CREATE_FILE 2>&1
         done
echo " " >> $CREATE_FILE 2>&1


echo " " > home.txt
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
         for dir in $HOMEDIRS
          do
               if [ -d $dir ]
               then
                if [ `ls -dal $dir |  awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
                then
                  echo "● 2.09 결과 : 양호" >> home.txt
                 else
                  echo "● 2.09 결과 : 취약" >> home.txt
                fi
              else
                echo "● 2.09 결과 : 양호" >> home.txt
              fi
         done

if [ `cat home.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.09 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.09 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf home.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.09 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "2.10 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.10. 홈 디렉터리 환경변수 파일권한 설정 #####################"
echo "############################ 2.파일시스템 - 2.10. 홈 디렉터리 환경변수 파일권한 설정 #####################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 홈디렉토리(/home) 아래 파일이 타사용자에게 쓰기 권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

for file in $FILES
  do
    FILE=/$file
    if [ -f $FILE ]
      then
        ls -al $FILE >> $CREATE_FILE 2>&1
    fi
  done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    FILE=$dir/$file
    if [ -f $FILE ]
      then
        ls -al $FILE >> $CREATE_FILE 2>&1
    fi
  done
done
echo " " >> $CREATE_FILE 2>&1

echo " " > home2.txt

HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

for file in $FILES
          do
            if [ -f /$file ]
             then
             if [ `ls -alL /$file |  awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
              then
                echo "● 2.10 결과 : 양호" >> home2.txt
              else
                echo "● 2.10 결과 : 취약" >> home2.txt
             fi
            else
              echo "● 2.10 결과 : 양호"   >> home2.txt
            fi
         done

 for dir in $HOMEDIRS
    do
        for file in $FILES
          do
            if [ -f $dir/$file ]
             then
             if [ `ls -al $dir/$file | awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
              then
                echo "● 2.10 결과 : 양호" >> home2.txt
              else
                echo "● 2.10 결과 : 취약" >> home2.txt
             fi
            else
              echo "● 2.10 결과 : 양호" >> home2.txt
            fi
         done
    done

if [ `cat home2.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.10 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.10 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf home2.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.10 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.11 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.11. 주요 디렉토리 파일권한 설정 ##########################"
echo "############################ 2.파일시스템 - 2.11. 주요 디렉토리 파일권한 설정 ##########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 주요 디렉터리(/sbin, /etc, /bin, /usr/bin, /usr/sbin, /usr/lbin)에 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS="/sbin /etc /bin /usr/bin /usr/sbin /usr/lbin"

         for dir in $HOMEDIRS
          do
            ls -dal $dir | grep '\d.........' >> $CREATE_FILE 2>&1
         done
echo " " >> $CREATE_FILE 2>&1


echo " " > home.txt
HOMEDIRS="/sbin /etc /bin /usr/bin /usr/sbin /usr/lbin"
         for dir in $HOMEDIRS
          do
               if [ -d $dir ]
               then
                if [ `ls -dal $dir | grep "........-." | wc -l` -eq 1 ]
                then
                  echo "● 2.11 결과 : 양호" >> home.txt
                 else
                  echo "● 2.11 결과 : 취약" >> home.txt
                fi
              else
                echo "● 2.11 결과 : 양호" >> home.txt
              fi
         done

if [ `cat home.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.11 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.11 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf home.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.11 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.12 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.12. PATH 환경변수 설정 #####################################"
echo "############################ 2.파일시스템 - 2.12. PATH 환경변수 설정 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 현재 위치를 의미하는 . 이 없거나, PATH 맨 뒤에 존재하면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo $PATH >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]
  then
    echo "● 2.12 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 2.12 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.12 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.13 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.13. ftp 접근제어 파일권한 설정 ############################"
echo "############################ 2.파일시스템 - 2.13. ftp 접근제어 파일권한 설정 ############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : ftpusers 파일이 타사용자(other) 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/ftpd/ftpusers ]
  then
   ls -alL /etc/ftpd/ftpusers  >> $CREATE_FILE 2>&1
  else
   echo " /etc/ftpd/ftpusers 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/ftpusers ]
  then
   ls -alL /etc/ftpusers  >> $CREATE_FILE 2>&1
  else
   echo " /etc/ftpusers 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/vsftpd/ftpusers ]
  then
   ls -alL /etc/vsftpd/ftpusers  >> $CREATE_FILE 2>&1
  else
   echo " /etc/vsftpd/ftpusers 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/vsftpd/user_list ]
  then
   ls -alL /etc/vsftpd/user_list >> $CREATE_FILE 2>&1
  else
   echo " /etc/vsftpd/user_list 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


echo "  " > ftpusers.txt

if [ -f /etc/ftpd/ftpusers ]
 then
     if [ `ls -alL /etc/ftpd/ftpusers | awk '{print $1}' | grep '........-.' | wc -l` -eq 0 ]
              then
                echo "● 2.13 결과 : 취약" >> ftpusers.txt
              else
                echo "● 2.13 결과 : 양호" >> ftpusers.txt
     fi
 else
  echo "no-file"  >> ftpusers.txt
fi

if [ -f /etc/ftpusers ]
then
 if [ `ls -alL /etc/ftpusers | awk '{print $1}' | grep '........-.'| wc -l` -eq 0 ]
   then
     echo "● 2.13 결과 : 취약" >> ftpusers.txt
   else
     echo "● 2.13 결과 : 양호" >> ftpusers.txt
 fi
else
  echo "no-file"  >> ftpusers.txt
fi

if [ -f /etc/vsftpd/ftpusers ]
then
if [ `ls -alL /etc/vsftpd/ftpusers | awk '{print $1}' | grep '........-.' | wc -l` -eq 0 ]
  then
    echo "● 2.13 결과 : 취약" >> ftpusers.txt
  else
    echo "● 2.13 결과 : 양호" >> ftpusers.txt
fi
else
  echo "no-file"  >> ftpusers.txt
fi

if [ -f /etc/vsftpd/user_list ]
then
if [ `ls -alL /etc/vsftpd/user_list | awk '{print $1}' | grep '........-.' | wc -l` -eq 0 ]
  then
    echo "● 2.13 결과 : 취약" >> ftpusers.txt
  else
    echo "● 2.13 결과 : 양호" >> ftpusers.txt
fi
else
  echo "no-file"  >> ftpusers.txt
fi


if [ `cat ftpusers.txt | grep "취약" | wc -l` -gt 0 ]
 then
   echo "● 2.13 결과 : 취약" >> $CREATE_FILE 2>&1
 else
   echo "● 2.13 결과 : 양호" >> $CREATE_FILE 2>&1
fi

rm -rf ftpusers.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.13 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.14 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.14. root 원격 접근제어 파일권한 설정  #####################"
echo "############################ 2.파일시스템 - 2.14. root 원격 접근제어 파일권한 설정  #####################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/pam.d/login 파일이 타사용자에게 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/login ]
  then
   ls -alL /etc/pam.d/login  >> $CREATE_FILE 2>&1
  else
   echo " /etc/pam.d/login 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1



if [ -f /etc/pam.d/login ]
  then
    if [ `ls -alL /etc/pam.d/login | awk '{print $1}' | grep '........-.' | wc -l` -eq 0 ]
       then
          echo "● 2.14 결과 : 취약" >> $CREATE_FILE 2>&1
       else
          echo "● 2.14 결과 : 양호" >> $CREATE_FILE 2>&1
    fi
  else
   echo "● 2.14 결과 : 양호"  >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.14 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.15 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.15. NFS 접근제어 파일 권한 설정 ###########################"
echo "############################ 2.파일시스템 - 2.15. NFS 접근제어 파일 권한 설정 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/exports파일이 타사용자 쓰기권한 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f  /etc/exports ]
  then
   ls -alL /etc/exports  >> $CREATE_FILE 2>&1
  else
   echo " /etc/exports 파일이 없습니다"  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/exports ]
  then
   if [ `ls -alL /etc/exports | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
       then
          echo "● 2.15 결과 : 양호" >> $CREATE_FILE 2>&1
       else
          echo "● 2.15 결과 : 취약" >> $CREATE_FILE 2>&1
   fi
  else
   echo "● 2.15 결과 : 양호" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.15 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "2.16 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.16. 서비스 파일 권한 설정 #################################"
echo "############################ 2.파일시스템 - 2.16. 서비스 파일 권한 설정 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/services이 타사용자에게 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/services ]
  then
   ls -alL /etc/services  >> $CREATE_FILE 2>&1
  else
   echo " /etc/services 파일이 없습니다"  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1



if [ -f /etc/services ]
then
  if [ `ls -alL /etc/services | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
              then
                echo "● 2.16 결과 : 양호" >> $CREATE_FILE 2>&1
              else
                echo "● 2.16 결과 : 취약" >> $CREATE_FILE 2>&1
  fi
else
  echo "● 2.16 결과 : 양호" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.16 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "2.17 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.17. 기타 중요파일 권한 설정 ###############################"
echo "############################ 2.파일시스템 - 2.17. 기타 중요파일 권한 설정 ###############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 기타 중요파일의 권한이 타사용자에게 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

DIR744="/etc/rc*.d/* /etc/inittab /etc/syslog.conf /etc/snmp/conf/snmpd.conf"

for check_dir in $DIR744
do

  if [ -f $check_dir ]
    then
      ls -alL $check_dir >> $CREATE_FILE 2>&1
    else
      echo $check_dir " 이 없습니다" >> $CREATE_FILE 2>&1
  fi
done
echo " " >> $CREATE_FILE 2>&1




DIR744="/etc/rc*.d/* /etc/inittab /etc/syslog.conf /etc/snmp/conf/snmpd.conf"

echo " " >> etcfiles.txt 2>&1
for check_dir in $DIR744
do

  if [  `ls -alL $check_dir | awk '{print $1}' | grep '........w.' | wc -l` -eq 0 ]
    then
      echo "● 2.17 결과 : 양호" >> etcfiles.txt 2>&1
    else
      echo "● 2.17 결과 : 취약" >> etcfiles.txt 2>&1
  fi
done


if [ `cat etcfiles.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.17 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.17 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf etcfiles.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.17 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1






echo "3.01 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.01. RPC 서비스 설정 ###################################"
echo "############################ 3.네트워크 서비스 - 3.01. RPC 서비스 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 불필요한 rpc 관련 서비스가 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

if [ -d /etc/xinetd.d ]
  then
    if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -eq 0 ]
      then
        echo " /etc/xinetd.d 디렉토리에 불필요한 서비스가 없음" >> $CREATE_FILE 2>&1
      else
        ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
    fi
  else
     echo "/etc/xinetd.d 디렉토리가 존재하지 않습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "/etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
echo "------------------ " >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
  then
     for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
         echo " $VVV 파일" >> $CREATE_FILE 2>&1
         cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
         echo "   " >> $CREATE_FILE 2>&1
        done
  else
      echo "xinetd.d에 파일이 없습니다" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/inetd.conf ]
  then
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
  else
    echo "/etc/inetd.conf 파일이 존재하지 않음 " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


echo " " > rpc.txt

SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

if [ -d /etc/xinetd.d ]
  then
   if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | awk '{print $9}'`
        do
        if [ `cat $VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "● 3.01 결과 : 취약" >> rpc.txt
          else
           echo "● 3.01 결과 : 양호" >> rpc.txt
        fi
        done
    else
      echo "● 3.01 결과 : 양호" >> rpc.txt
    fi
elif [ -f /etc/inetd.conf ]
  then
    if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l` -eq 0 ]
              then
                 echo "● 3.01 결과 : 양호" >> rpc.txt
              else
                 echo "● 3.01 결과 : 취약" >> rpc.txt
    fi
  else
   :
fi


if [ `cat rpc.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 3.01 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 3.01 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf rpc.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.02 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.02. NFS 설정  #########################################"
echo "############################ 3.네트워크 서비스 - 3.02. NFS 설정  #########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : NFS가 중지되어 있거나 NFS 설정파일에 Everyone 공유가 없을 경우에 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ NFS 데몬(nfsd)확인" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ps -ef | grep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -al /etc/rc*.d/* | grep -i nfs | grep "/S" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -gt 0 ]
 then
  if [ -f /etc/exports ]
   then
    cat /etc/exports  >> $CREATE_FILE 2>&1
   else
    echo "/etc/exports 파일이 존재하지 않음"  >> $CREATE_FILE 2>&1
  fi
 else
  echo "NFS 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
fi


echo " " >> $CREATE_FILE 2>&1


if [ `ps -ef | egrep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "● 3.02 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  if [ -f /etc/exports ]
    then
     if [ `cat /etc/exports | grep -v "#" | grep "/" | wc -l` -eq 0 ]
       then
         echo "● 3.02 결과 : 양호" >> $CREATE_FILE 2>&1
       else
         echo "● 3.02 결과 : 미점검" >> $CREATE_FILE 2>&1
     fi
    else
     echo "● 3.02 결과 : 양호"  >> $CREATE_FILE 2>&1
  fi
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.03 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.03. 원격 마운트시스템 확인 ###########################"
echo "############################ 3.네트워크 서비스 - 3.03. 원격 마운트시스템 확인 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : NFS 서비스가 비실행중이거나 showmount값이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

ps -ef | grep "nfsd" | grep -v "grep" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep nfsd | grep -v "grep" | wc -l` -gt 0 ]
 then
   echo "☞ NFS를 원격에서 mount하고 있는 시스템을 확인 " >> $CREATE_FILE 2>&1
   showmount  >> $CREATE_FILE 2>&1
 else
   echo "NFS 서비스가 비실행중입니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep nfsd | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "● 3.03 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 3.03 결과 : 미점검" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1






echo "3.04 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.04. statd, lockd 제거  ################################"
echo "############################ 3.네트워크 서비스 - 3.04. statd, lockd 제거  ################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : statd, lockd 서비스가 구동중이지 않을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ NFS 데몬(statd,lockd)확인" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ps -ef | egrep "statd|lockd" | egrep -v "grep|statdaemon|emi|kblockd" | grep -v "grep" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -al /etc/rc*.d/* | grep -i nfs | grep "/S" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|statdaemon|emi|kblockd" | wc -l` -eq 0 ]
then
  echo "statd, lockd 데몬이 없습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|statdaemon|emi|kblockd" | wc -l` -eq 0 ]
  then
    echo "● 3.04 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 3.04 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.05 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.05. automountd 제거 ###################################"
echo "############################ 3.네트워크 서비스 - 3.05. automountd 제거 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : automount 서비스가 구동중이지 않을 경우에 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "☞ Automount 데몬 확인 " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ps -ef | egrep 'automountd|autofs' | grep -v "grep" | egrep -v "grep|statdaemon|emi" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -al /etc/rc*.d/* | grep -i "auto" | grep "/S" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | egrep 'automountd|autofs' | grep -v "grep" | egrep -v "grep|statdaemon|emi"  | wc -l` -eq 0 ]
  then
    echo "automount 데몬이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


if [ `ps -ef | egrep 'automountd|autofs' | grep -v "grep" | egrep -v "grep|statdaemon|emi" | wc -l` -eq 0 ]
  then
     echo "● 3.05 결과 : 양호" >> $CREATE_FILE 2>&1
  else
     echo "● 3.05 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.06 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.06. NIS, NIS+ 점검 ####################################"
echo "############################ 3.네트워크 서비스 - 3.06. NIS, NIS+ 점검 ####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : NIS, NIS+ 서비스가 구동중이지 않을 경우에 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
   then
    echo "NIS, NIS+ 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
   else
    ps -ef | egrep $SERVICE | grep -v "grep" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
     then
        echo "● 3.06 결과 : 양호" >> $CREATE_FILE 2>&1
     else
        echo "● 3.06 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.07 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.07. ‘r' commands 설정 #################################"
echo "############################ 3.네트워크 서비스 - 3.07. ‘r' commands 설정 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : rsh, rlogin, rexec (shell, login, exec) 서비스가  구동중이지 않을 경우에 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

SERVICE_INETD="rsh|rlogin|rexec"

if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD |egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
   then
 ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
else
 echo "r 서비스가 존재하지 않음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "/etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
echo "------------------ " >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
  then
     for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
        do
         echo " $VVV 파일" >> $CREATE_FILE 2>&1
         cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
         echo "   " >> $CREATE_FILE 2>&1
        done
  else
      echo "xinetd.d에 파일이 없습니다" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

SERVICE_INETD="shell|login|exec"

if [ -f /etc/inetd.conf ]
  then
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" >> $CREATE_FILE 2>&1
  else
    echo "/etc/inetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -d /etc/xinetd.d ]
  then
   SERVICE_INETD="rsh|rlogin|rexec"
   if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
        do
        if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "● 3.07 결과 : 취약" >> CREATE_FILE 2>&1
           echo "r command" > r_temp
          else
           echo "● 3.07 결과 : 양호" >> $CREATE_FILE 2>&1
        fi
        done
    else
      echo "● 3.07 결과 : 양호" >> $CREATE_FILE 2>&1
    fi
 elif [ -f /etc/inetd.conf ]
  then
    if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" |wc -l` -eq 0 ]
     then
        echo "● 3.07 결과 : 양호" >> $CREATE_FILE 2>&1
     else
        echo "● 3.07 결과 : 취약" >> $CREATE_FILE 2>&1
        echo "r command" > r_temp
    fi
  else
     echo "● 3.07 결과 : 양호" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.07 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "3.08 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.08. 신뢰관계 설정 #####################################"
echo "############################ 3.네트워크 서비스 - 3.08. 신뢰관계 설정 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : r 서비스를 사용하지 않거나,  + 가 설정되어 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
FILES="/.rhosts"

if [ -s r_temp ]
then
 if [ -f /etc/hosts.equiv ]
 then
  echo "① /etc/hosts.equiv 파일 설정 내용" >> $CREATE_FILE 2>&1
  cat /etc/hosts.equiv >> $CREATE_FILE 2>&1
 else
  echo "① /etc/hosts.equiv 파일 설정 내용" >> $CREATE_FILE 2>&1
  echo "해당 파일 없음" >> $CREATE_FILE 2>&1
 fi
 echo " " >> $CREATE_FILE 2>&1

 echo "② 사용자 home directory .rhosts 설정 내용" >> $CREATE_FILE 2>&1

   for dir in $HOMEDIRS
   do
     for file in $FILES
     do
       if [ -f $dir$file ]
       then
        ls -al $dir$file  >> $CREATE_FILE 2>&1
        echo "- $dir$file 설정 내용" >> $CREATE_FILE 2>&1
        cat $dir$file | grep -v "#" >> $CREATE_FILE 2>&1
        echo " " >> $CREATE_FILE 2>&1
       fi
      done
   done
else
 echo "r 서비스가 운영중이지 않음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo " " > trust.txt

if [ -f /etc/inetd.conf ]
  then
  if [ -s r_temp ]
   then
       if [ -f /etc/hosts.equiv ]
       then
              if [ `cat /etc/hosts.equiv | grep "+" | grep -v "grep" | grep -v "#" | wc -l ` -eq 0 ]
               then
                 echo "● 3.08 결과 : 양호" >> trust.txt
               else
                 echo "● 3.08 결과 : 취약" >> trust.txt
              fi
        else
         echo "● 3.08 결과 : 양호" >> trust.txt
        fi

	for dir in $HOMEDIRS
	do
	  for file in $FILES
	  do
	    if [ -f $dir$file ]
	      then
	        if [ `cat $dir$file | grep "+" | grep -v "grep" | grep -v "#" |wc -l ` -eq 0 ]
	         then
	          echo "● 3.08 결과 : 양호" >> trust.txt
	         else
	          echo "● 3.08 결과 : 취약" >> trust.txt
	        fi
	      else
	      echo "● 3.08 결과 : 양호" >> trust.txt
	    fi
	  done
	done
    else
     echo "● 3.08 결과 : 양호" >> trust.txt
    fi
  else
  echo "● 3.08 결과 : 양호 " >> trust.txt
fi

if [ `cat trust.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 3.08 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 3.08 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf trust.txt r_temp

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.09 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.09. hosts.equiv 파일 권한 설정 ########################"
echo "############################ 3.네트워크 서비스 - 3.09. hosts.equiv 파일 권한 설정 ########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 설정 파일의 권한이 400(600) 이거나 존재하지 않을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/hosts.equiv ]
then
 ls -al /etc/hosts.equiv >> $CREATE_FILE 2>&1
else
 echo "해당 파일 없음" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/hosts.equiv ]
then
    if [ `ls -al /etc/hosts.equiv | awk '{print $1}' | grep '...-------' | wc -l ` -eq 1 ]
     then
       echo "● 3.09 결과 : 양호" >> $CREATE_FILE 2>&1
     else
       if [ `ls -al /etc/hosts.equiv | grep '\/dev\/null' | wc -l` -eq 1 ]
          then
           echo "● 3.09 결과 : 양호" >> $CREATE_FILE 2>&1
          else
           echo "● 3.09 결과 : 취약" >> $CREATE_FILE 2>&1
       fi
    fi
else
  echo "● 3.09 결과 : 양호" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.09 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.10 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.10. .rhosts 파일 권한 설정 ###########################"
echo "############################ 3.네트워크 서비스 - 3.10. .rhosts 파일 권한 설정 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 설정 파일의 권한이 400(600) 이거나 존재하지 않을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
FILES="/.rhosts"

for dir in $HOMEDIRS
   do
     for file in $FILES
     do
       if [ -f $dir$file ]
       then
        echo "- $dir/.rhosts 권한 설정" >> $CREATE_FILE 2>&1
        ls -al $dir$file  >> $CREATE_FILE 2>&1
        echo " " >> $CREATE_FILE 2>&1
       fi
      done
   done

echo "  " > rhosts.txt

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    if [ -f $dir$file ]
     then
       if [ `ls -al $dir$file | awk '{print $1}' | grep '...-------' | wc -l` -eq 1 ]
       then
         echo "● 3.10 결과 : 양호" >> rhosts.txt
       else
         if [ `ls -al $dir$file | grep '\/dev\/null' | wc -l` -eq 1 ]
          then
           echo "● 3.10 결과 : 양호" >> rhosts.txt
          else
           echo "● 3.10 결과 : 취약" >> rhosts.txt
         fi
       fi
     else
       echo "● 3.10 결과 : 양호" >> rhosts.txt
     fi
  done
done


if [ `cat rhosts.txt | grep "취약" | wc -l` -gt 0 ]
 then
  echo "● 3.10 결과 : 취약" >> $CREATE_FILE 2>&1
 else
  echo "● 3.10 결과 : 양호" >> $CREATE_FILE 2>&1
fi

rm -rf rhosts.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.10 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1






echo "3.11 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.11. 기타 서비스 설정 #################################"
echo "############################ 3.네트워크 서비스 - 3.11. 기타 서비스 설정 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 불필요한 서비스가 사용되고 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SERVICE_INETD="echo|discard|daytime|chargen|time|tftp|finger|sftp|uucp-path|nntp|ntp|netbios_ns|netbios_dgm|netbios_ssn|bftp|ldap|printer|talk|ntalk|uucp|pcserver|ldaps|ingreslock|www-ldap-gw|nfsd|dtspcd"

echo "/etc/xinetd.d 내용" >> $CREATE_FILE 2>&1
echo "--------------------" >> $CREATE_FILE 2>&1

if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -gt 0 ]
   then
 ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
else
 echo "불필요한 서비스가 존재하지 않음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "/etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
echo "------------------ " >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
  then
     for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
         echo " $VVV 파일" >> $CREATE_FILE 2>&1
         cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
         echo "   " >> $CREATE_FILE 2>&1
        done
  else
      echo "xinetd.d에 파일이 없습니다" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


echo " " > service.txt

if [ -f /etc/inetd.conf ]
 then
  if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -eq 0 ]
      then
       echo "● 3.11 결과 : 양호" >> service.txt
      else
       echo "● 3.11 결과 : 취약" >> service.txt
  fi
 else
  echo "● 3.11 결과 : 양호" >> service.txt
fi

if [ -d /etc/xinetd.d ]
  then
   if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
        if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "● 3.11 결과 : 취약" >> service.txt
          else
           echo "● 3.11 결과 : 양호" >> service.txt
        fi
        done
    else
      echo "● 3.11 결과 : 양호" >> service.txt
    fi
  else
    echo "● 3.11 결과 : 양호" >> service.txt
fi

if [ `cat service.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 3.11 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 3.11 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf service.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.11 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1






echo "3.12 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.12. 서비스 Banner 관리 ###############################"
echo "############################ 3.네트워크 서비스 - 3.12. 서비스 Banner 관리 ###############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : Telnet, FTP, SMTP, DNS 가 구동중이지 않거나 배너에 O/S 및 버전 정보가 없을 경우" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -d /etc/xinetd.d ]
  then
   if [ `ls -alL /etc/xinetd.d | grep "telnet" | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | grep telnet | awk '{print $9}'`
        do
        if [ `cat $VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "telnet enable" >> telnetps.txt
        fi
        done
    fi
  else
   if [ -f /etc/inetd.conf ]
    then
     if [ `cat /etc/inetd.conf | grep -v '^ *#' | grep telnet | wc -l` -gt 0 ]
      then
      echo "telnet enable" >> telnetps.txt
    fi
  fi
fi

ps -ef | grep telnetd  | grep -v grep >> telnetps.txt
cat /etc/issue >> telnetbanner.txt
cat /etc/issue.net >> telnetbanner.txt

if [ `cat telnetps.txt | grep telnet | grep -v grep | wc -l` -gt 0 ]
 then
     echo "☞ Telnet 서비스 구동됨" >> $CREATE_FILE 2>&1
     echo "■ TELNET 배너" >> $CREATE_FILE 2>&1
    if [ `cat telnetbanner.txt | egrep "Linux|Kernel" | grep -v grep | wc -l` -eq 0 ]
    then
       echo "● 3.12 결과 : 양호" >> banner.txt
       ls -al /etc/issue >> $CREATE_FILE 2>&1
       cat /etc/issue >> $CREATE_FILE 2>&1
       echo " " >> $CREATE_FILE 2>&1
       ls -al /etc/issue.net >> $CREATE_FILE 2>&1
       cat /etc/issue.net >> $CREATE_FILE 2>&1
    else
       echo "● 3.12 결과 : 취약" >> banner.txt
       ls -al /etc/issue >> $CREATE_FILE 2>&1
       cat /etc/issue >> $CREATE_FILE 2>&1
       echo " " >> $CREATE_FILE 2>&1
       ls -al /etc/issue.net >> $CREATE_FILE 2>&1
       cat /etc/issue.net >> $CREATE_FILE 2>&1
   fi
 else
   echo "● 3.12 결과 : 양호" >> banner.txt
   echo "☞ Telnet 서비스 비 실행중" >> $CREATE_FILE 2>&1
fi

rm -rf telnetbanner.txt

if [ -d /etc/xinetd.d ]
  then
   if [ `ls -alL /etc/xinetd.d | grep "ftp" | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | grep ftp | grep -v "tftp" | gerp -v "sftp" | awk '{print $9}'`
        do
        if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "ftp enable" >> ftpps.txt
           echo "/etc/xinetd.d/ FTP 구동 정보" >> $CREATE_FILE 2>&1
           ls -alL /etc/xinetd.d | grep ftp | grep -v "tftp" | gerp -v "sftp"  >> $CREATE_FILE 2>&1
           cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        fi
        done
    fi
  else
   if [ -f /etc/inetd.conf ]
    then
     if [ `cat /etc/inetd.conf | grep -v '#' | grep ftp  | grep -v "tftp" | gerp -v "sftp" | wc -l` -gt 0  ]
      then
      echo "ftp enable" >> ftpps.txt
    fi
  fi
fi

ps -ef | grep ftp  | grep -v grep | grep -v "tftp" | gerp -v "sftp" >> ftpps.txt
echo " " >> $CREATE_FILE 2>&1

if [ `cat ftpps.txt | grep ftp | grep -v grep | wc -l` -gt 0 ]
 then
     echo "☞ FTP 서비스 구동됨" >> $CREATE_FILE 2>&1
     echo "- FTP 배너" >> $CREATE_FILE 2>&1

  if [ -f /etc/welcome.msg ]
    then
       if [ `cat /etc/welcome.msg | grep -i "banner" | grep "=" | grep "\".\"" | wc -l` -eq 0 ]
        then
          echo "● 3.12 결과 : 취약" >> banner.txt
          cat /etc/welcome.msg >> $CREATE_FILE 2>&1
          echo " " >> $CREATE_FILE 2>&1
        else
          echo "● 3.12 결과 : 양호" >> banner.txt
          cat /etc/welcome.msg >> $CREATE_FILE 2>&1
          echo " " >> $CREATE_FILE 2>&1
       fi
    else
      if [ -f /etc/vsftpd/vsftpd.conf ]
         then
           if [ `cat /etc/vsftpd/vsftpd.conf | grep -i "ftp_banner" | grep "=" | wc -l` -eq 0 ]
             then
               echo "● 3.12 결과 : 취약" >> banner.txt
               cat /etc/vsftpd/vsftpd.conf | grep -i "ftp_banner" >> $CREATE_FILE 2>&1
             else
               echo "● 3.12 결과 : 양호" >> banner.txt
               cat /etc/vsftpd/vsftpd.conf | grep -i "ftp_banner" >> $CREATE_FILE 2>&1
           fi
         else
          if [ -f /etc/proftpd.conf ]
            then
              if [ `cat /etc/proftpd.conf | grep -i "Serverldent" | grep -i "off" | wc -l` -eq 0 ]
                then
                  echo "● 3.12 결과 : 취약" >> banner.txt
                  cat /etc/proftpd.conf | grep -i "Serverldent" >> $CREATE_FILE 2>&1
                else
              	  echo "● 3.12 결과 : 양호" >> banner.txt
                  cat /etc/proftpd.conf  | grep -i "Serverldent" >> $CREATE_FILE 2>&1
              fi
            else
            if [ -f /usr/local/etc/proftpd.conf ]
            then
              if [ `cat /usr/local/etc/proftpd.conf | grep -i "Serverldent" | grep -i "off" | wc -l` -eq 0 ]
                then
                  echo "● 3.12 결과 : 취약" >> banner.txt
                  cat /usr/local/etc/proftpd.conf | grep -i "Serverldent" >> $CREATE_FILE 2>&1
                else
              	  echo "● 3.12 결과 : 양호" >> banner.txt
              	  cat /usr/local/etc/proftpd.conf | grep -i "Serverldent" >> $CREATE_FILE 2>&1
              fi
            else
              if [ -f /etc/ftpaccess ]
                then
                  if [ `cat /etc/ftpaccess | grep -i "greeting" | grep -i "terse" | wc -l` -eq 0 ]
                     then
                       echo "● 3.12 결과 : 취약" >> banner.txt
                       cat /etc/ftpaccess | grep -i "greeting" | grep -i "terse" >> $CREATE_FILE 2>&1
                     else
              	       echo "● 3.12 결과 : 양호" >> banner.txt
                       cat /etc/ftpaccess | grep -i "greeting" | grep -i "terse" >> $CREATE_FILE 2>&1
                  fi
               else
                  echo "● 3.12 결과 : 미점검" >> banner.txt
              fi
            fi
          fi
      fi
  fi
 else
    echo "● 3.12 결과 : 양호" >> banner.txt
    echo "☞ ftp 서비스 비 실행중" >> $CREATE_FILE 2>&1
fi

echo "  " >> $CREATE_FILE 2>&1


echo " " > banner_temp.txt
echo "  " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ]
 then
     echo "☞ SMTP 서비스 구동됨" >> $CREATE_FILE 2>&1
     echo "■ SMTP 배너" >> $CREATE_FILE 2>&1
   if [ -f /etc/mail/sendmail.cf ]
     then
       if [ `cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" | grep -i "Sendmail" | wc -l` -gt 0 ]
         then
           echo "● 3.12 결과 : 취약" >> banner.txt
           echo "/etc/mail/sendmail.cf 파일 내용" >> $CREATE_FILE 2>&1
           cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
         else
           echo "● 3.12 결과 : 양호" >> banner.txt
           echo "/etc/mail/sendmail.cf 파일 내용" >> $CREATE_FILE 2>&1
           cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
       fi
     else
       echo "● 3.12 결과 : 미점검" >> banner.txt
       echo "/etc/mail/sendmail.cf 파일 존재하지 않음" >> $CREATE_FILE 2>&1
   fi
 else
  echo "● 3.12 결과 : 양호" >> banner.txt
  echo "☞ SMTP 서비스 구동중이지 않음" >> $CREATE_FILE 2>&1
fi


echo "  " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]
  then
     echo "☞ DNS 서비스 구동됨" >> $CREATE_FILE 2>&1
     echo "■ DNS 배너" >> $CREATE_FILE 2>&1
    if [ -f /etc/named.conf ]
      then
        if [ `cat /etc/named.conf | grep "version" | wc -l` -eq 0 ]
          then
            echo "● 3.12 결과 : 취약" >> banner.txt
           echo "/etc/named.conf 파일 내용" >> $CREATE_FILE 2>&1
           echo "/etc/named.conf 파일 설정 없음" >> $CREATE_FILE 2>&1
         else
           echo "● 3.12 결과 : 양호" >> banner.txt
           echo "/etc/named.conf 파일 내용" >> $CREATE_FILE 2>&1
           cat /etc/named.conf | grep -i "version" >> $CREATE_FILE 2>&1
       fi
     else
       echo "● 3.12 결과 : 미점검" >> banner.txt
       echo "/etc/named.conf 파일 존재하지 않음" >> $CREATE_FILE 2>&1
   fi
 else
  echo "● 3.12 결과 : 양호" >> banner.txt
  echo "☞ DNS 서비스 구동중이지 않음" >> $CREATE_FILE 2>&1
fi

echo "  " >> $CREATE_FILE 2>&1

if [ `cat banner.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 3.12 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 3.12 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf banner.txt
rm -rf banner_temp.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.12 END" >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.13 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.13. session timeout 설정 #############################"
echo "############################ 3.네트워크 서비스 - 3.13. session timeout 설정 #############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/profile 에서 TMOUT=300 또는 /etc/csh.login 에서 autologout=5 로 설정되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ /etc/profile 파일설정" >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
 then
    cat /etc/profile | grep -i TMOUT >> $CREATE_FILE 2>&1
 else
  echo "/etc/profile 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ /etc/csh.login 파일설정" >> $CREATE_FILE 2>&1
if [ -f /etc/csh.login ]
 then
    cat /etc/csh.login | grep -i autologout >> $CREATE_FILE 2>&1
 else
  echo "/etc/csh.login 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/profile ]
 then
  if [ `cat /etc/profile | grep -v "#" | grep -i 'TMOUT' | grep -v '[0-9]300' | grep '300$' | wc -l ` -eq 1 ]
      then
       echo "● 3.13 결과 : 양호" >> $CREATE_FILE 2>&1
      else
        if [ -f /etc/csh.login  ]
         then
           if [ `cat /etc/csh.login  | grep -v "#" | grep -i 'autologout' | grep -v '[0-9]5' | grep '5$' | wc -l ` -eq 1 ]
            then
              echo "● 3.13 결과 : 양호" >> $CREATE_FILE 2>&1
            else
              echo "● 3.13 결과 : 취약" >> $CREATE_FILE 2>&1
           fi
        else
        echo "● 3.13 결과 : 취약" >> $CREATE_FILE 2>&1
   fi
  fi
 else
  if [ -f /etc/csh.login  ]
         then
           if [ `cat /etc/csh.login  | grep -v "#" | grep -i 'autologout' | grep -v '[0-9]5' | grep '5$' | wc -l ` -eq 1 ]
            then
              echo "● 3.13 결과 : 양호" >> $CREATE_FILE 2>&1
            else
              echo "● 3.13 결과 : 취약" >> $CREATE_FILE 2>&1
           fi
        else
        echo "● 3.13 결과 : 취약" >> $CREATE_FILE 2>&1
   fi
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.13 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "3.14 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.14. root 계정의 telnet 및 ssh 제한 ##########################"
echo "############################ 3.네트워크 서비스 - 3.14. root 계정의 telnet 및 ssh 제한 ##########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : [Telnet] /etc/pam.d/login에서 auth required /lib/security/pam_securetty.so 라인에 주석(#) 이 없으면 양호" >> $CREATE_FILE 2>&1
echo "         [SSH] /etc/ssh/sshd_config에서 PermitRootLogin no 이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "[Telnet]" >> $CREATE_FILE 2>&1

if [ `cat /etc/pam.d/login | grep "pam_securetty.so" | grep -v "#" | wc -l` -gt 0 ]
  then
    cat /etc/pam.d/login | grep "pam_securetty.so" | grep -v "#" >> $CREATE_FILE 2>&1
  else
    echo "/etc/pam.d/login 파일에 설정값이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo "[SSH]" >> $CREATE_FILE 2>&1

if [ -f /etc/ssh/sshd_config ]
  then
    cat /etc/ssh/sshd_config | grep "PermitRootLogin" | grep -v "grep" >> $CREATE_FILE 2>&1
  else
    echo "/etc/ssh/sshd_config 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo " " > sshps_temp.txt

ps -ef | grep sshd | grep -v "grep" >> sshps_temp.txt

echo " " > result_314.txt

echo "[telnet]" >> result_314.txt

if [ `cat telnetps.txt | grep telnet | grep -v grep | wc -l` -gt 0 ]
  then
   if [ -f /etc/pam.d/login ]
    then
     if [ `grep "pam_securetty.so" /etc/pam.d/login | grep -v '#' | wc -l  ` -eq 1 ]
      then
       echo "● 3.14 결과 : 양호" >> result_314.txt 2>&1
      else
       echo "● 3.14 결과 : 취약" >> result_314.txt 2>&1
     fi
    else
     echo "● 3.14 결과 : 취약" >> result_314.txt 2>&1
   fi
  else
   echo "☞ Telnet 서비스 비 실행중" >> result_314.txt 2>&1
   echo "● 3.14 결과 : 양호" >> result_314.txt 2>&1
fi

echo "[ssh]" >> result_314.txt

if [ `cat sshps_temp.txt | grep sshd | grep -v grep | wc -l` -gt 0 ]
   then
    if [ -f /etc/ssh/sshd_config ]
     then
      if [ `cat /etc/ssh/sshd_config | grep "PermitRootLogin" | grep -v 'grep' | grep -v "#" | grep -i "no" | wc -l` -eq 0 ]
       then
        echo "● 3.14 결과 : 취약" >> result_314.txt 2>&1
       else
        echo "● 3.14 결과 : 양호" >> result_314.txt 2>&1
      fi
     else
      echo "● 3.14 결과 : 취약" >> result_314.txt 2>&1
    fi
   else
    echo "☞ SSH 서비스 비 실행중" >> result_314.txt 2>&1
    echo "● 3.14 결과 : 양호" >> result_314.txt 2>&1
fi


if [ `cat result_314.txt | grep "취약" | wc -l` -gt 0 ]
  then
    echo "● 3.14 결과 : 취약" >> $CREATE_FILE 2>&1
  else
    echo "● 3.14 결과 : 양호" >> $CREATE_FILE 2>&1
fi

rm -rf sshps_temp.txt
rm -rf result_314.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.14 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "4.01 START" >> $CREATE_FILE 2>&1
echo "############################ 4.로그관리 - 4.01. su 로그 설정 #############################################"
echo "############################ 4.로그관리 - 4.01. su 로그 설정 #############################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/login.defs 파일에 SULOG_FILE /var/log/sulog 또는 /etc/syslog.conf 파일에 authpriv.* /var/log/secure가 설정되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "☞ syslog 프로세스" >> $CREATE_FILE 2>&1
ps -ef | grep 'syslog' | grep -v 'grep' >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "☞ 시스템 로깅 설정" >> $CREATE_FILE 2>&1
if [ -f /etc/login.defs ]
  then
    echo "[/etc/login.defs 파일 점검]" >> $CREATE_FILE 2>&1
    if [ `cat /etc/login.defs | grep -i "SULOG_FILE" | grep -v '#' | wc -l` -gt 0 ]
      then
        cat /etc/login.defs | grep -i "SULOG_FILE" >> $CREATE_FILE 2>&1
      else
        echo "해당 설정 없음" >> $CREATE_FILE 2>&1
    fi
  else
    echo "/etc/login.defs 파일없음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/syslog.conf ]
  then
    echo "[/etc/syslog.conf  파일 점검]" >> $CREATE_FILE 2>&1
    if [ `cat /etc/syslog.conf | grep -i "authpriv" | grep -v '#' | wc -l` -gt 0 ]
      then
        cat /etc/syslog.conf | grep -i "auth.notice" | grep -v '#' >> $CREATE_FILE 2>&1
        cat /etc/syslog.conf | grep -i "authpriv" | grep -v '#' >> $CREATE_FILE 2>&1
      else
        echo "해당 설정 없음" >> $CREATE_FILE 2>&1
    fi
  else
    echo "/etc/syslog.conf 파일없음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/rsyslog.conf ]
  then
    echo "[/etc/rsyslog.conf  파일 점검]" >> $CREATE_FILE 2>&1
    if [ `cat /etc/rsyslog.conf | grep -i "authpriv" | grep -v '#' | wc -l` -gt 0 ]
      then
        cat /etc/rsyslog.conf | grep -i "auth.notice" | grep -v '#' >> $CREATE_FILE 2>&1
        cat /etc/rsyslog.conf | grep -i "authpriv" | grep -v '#' >> $CREATE_FILE 2>&1
      else
        echo "해당 설정 없음" >> $CREATE_FILE 2>&1
    fi
  else
    echo "/etc/rsyslog.conf 파일없음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/login.defs ]
  then
    if [ `cat /etc/login.defs | grep -i "SULOG_FILE" | grep -v '#' | egrep 'var|log' | wc -l` -gt 0 ]
      then
        echo "● 4.01 결과 : 양호" >> $CREATE_FILE 2>&1
      else
        if [ -f /etc/syslog.conf ]
          then
            if [ `cat /etc/syslog.conf | egrep -i "auth.notice|authpriv" | egrep 'var|log' | grep -v "#" | wc -l` -eq 0 ]
              then
                echo "● 4.01 결과 : 취약" >> $CREATE_FILE 2>&1
              else
                echo "● 4.01 결과 : 양호" >> $CREATE_FILE 2>&1
            fi
          else
	    if [ -f /etc/rsyslog.conf ]
	      then
	        if [ `cat /etc/rsyslog.conf | egrep -i "auth.notice|authpriv" | egrep 'var|log' | grep -v "#" | wc -l` -eq 0 ]
		  then
		    echo "● 4.01 결과 : 취약" >> $CREATE_FILE 2>&1
		  else
		    echo "● 4.01 결과 : 양호" >> $CREATE_FILE 2>&1
		fi
	      else
	        echo "● 4.01 결과 : 취약" >> $CREATE_FILE 2>&1
	    fi
        fi
    fi
  else
    echo "● 4.01 결과 : 취약" >> $CREATE_FILE 2>&1
fi


echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "4.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "4.02 START" >> $CREATE_FILE 2>&1
echo "############################ 4.로그관리 - 4.02. 로그파일 권한 설정 ######################################"
echo "############################ 4.로그관리 - 4.02. 로그파일 권한 설정 ######################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 로그 파일의 권한중 타사용자에 쓰기권한이 부여되어 있지 않을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황 " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
FILES="/var/log/wtmp /var/wtmp /var/run/utmp /var/utmp /var/log/btmp /var/log/pacct /var/log/messages /var/log/lastlog /var/log/secure"

for file in $FILES
do
  if [ -f $file ]
    then
      ls -al $file >> $CREATE_FILE 2>&1
  fi
done

echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo " " > logfiles.txt

FILES="/var/log/wtmp /var/wtmp /var/run/utmp /var/utmp /var/log/btmp /var/log/pacct /var/log/messages /var/log/lastlog /var/log/secure"

for file in $FILES
   do
        if [ -f $file ]
         then
          if [ `ls -al $file | awk '{print $1}' | grep '........w.' | wc -l` -gt 0 ]
          then
           echo "● 4.02 결과 : 취약" >> logfiles.txt 2>&1
          else
           echo "● 4.02 결과 : 양호" >> logfiles.txt 2>&1
          fi
        else
          echo "● 4.02 결과 : 양호" >> logfiles.txt 2>&1
        fi
done

if [ `cat logfiles.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 4.02 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 4.02 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf logfiles.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "4.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "5.01 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.01. FTP 서비스 사용자 제한 ###########################"
echo "############################ 5.주요 응용 설정 - 5.01. FTP 서비스 사용자 제한 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : ftp 를 사용하지 않거나 ftp 사용시 ftpusers 파일에 root 가 주석처리 안되어 있을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

ps -ef | grep ftp  | grep -v grep | grep -v "tftp" | grep -v "sftp" >> ftpps.txt
echo " " >> $CREATE_FILE 2>&1

if [ `cat ftpps.txt | grep ftp | grep -v grep | wc -l` -gt 0 ]
 then
     echo "☞ FTP 서비스 구동됨, ftpusers 설정을 통해 root 접속 제한 필요" >> $CREATE_FILE 2>&1
 else
     echo "☞ FTP 서비스 미사용" >> $CREATE_FILE 2>&1
fi

if [ `cat ftpps.txt | grep ftp | grep -v grep | wc -l` -gt 0 ]
 then
  if [ -f /etc/ftpd/ftpusers ]
   then
     cat /etc/ftpd/ftpusers  >> $CREATE_FILE 2>&1
   else
     echo "/etc/ftpd/ftpusers  파일 없음" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/ftpusers ]
   then
    cat /etc/ftpusers >> $CREATE_FILE 2>&1
   else
    echo "/etc/ftpusers  파일 없음" >> $CREATE_FILE 2>&1
  fi

  if [ -f /etc/vsftpd/vsftpd.ftpusers ]
   then
    echo "/etc/vsftpd/vsftpd.ftpusers 파일(root 없으면 취약) : `cat /etc/vsftpd/vsftpd.ftpusers | grep root | grep -v '#'`" >> $CREATE_FILE 2>&1
   else
    echo "/etc/vsftpd/vsftpd.ftpusers 파일이 없습니다. " >> $CREATE_FILE 2>&1
  fi

  if [ -f /etc/vsftpd/user_list ]
   then
    echo " /etc/vsftpd/user_list 파일(root 없으면 취약) : `cat /etc/vsftpd/user_list | grep root | grep -v '#'`" >> $CREATE_FILE 2>&1
   else
    echo "/etc/vsftpd/user_list 파일이 없습니다. " >> $CREATE_FILE 2>&1
  fi

 else
  echo "☞ ftp 서비스 비 실행중" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo " " > ftp.txt

cat /etc/ftpusers | grep root | grep -v '#' >> ftp.txt
cat /etc/ftpd/ftpusers | grep root | grep -v '#' >> ftp.txt
cat /etc/vsftpd/ftpusers | grep root | grep -v '#' >> ftp.txt
cat /etc/vsftpd/user_list | grep root | grep -v '#' >> ftp.txt

if [ `cat ftpps.txt | grep ftp | grep -v grep | wc -l` -gt 0 ]
then
   if [ `cat ftp.txt | grep root | grep -v grep | wc -l` -gt 0 ]
    then
     echo "● 5.01 결과 : 양호" >> $CREATE_FILE 2>&1
   else
     echo "● 5.01 결과 : 취약" >> $CREATE_FILE 2>&1
   fi

else
 echo "● 5.01 결과 : 양호" >> $CREATE_FILE 2>&1
fi

rm -rf ftp.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "5.02 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.02. FTP UMASK 설정 ###################################"
echo "############################ 5.주요 응용 설정 - 5.02. FTP UMASK 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : ftp 를 사용하지 않거나, ftp 사용시 ftp umask 가 077 로 설정되어 있을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


if [ `cat ftpps.txt | grep ftp | grep -v | wc -l` -gt 0 ]
then
  if [ -f /etc/ftpd.conf ]
   then
    echo "① /etc/ftpd.conf 파일 " >> $CREATE_FILE 2>&1
    cat /etc/ftpd.conf | grep -i "umask" >> $CREATE_FILE 2>&1
    echo " " >> $CREATE_FILE 2>&1
   else
    echo "① /etc/ftpd.conf 파일 " >> $CREATE_FILE 2>&1
    echo "/etc/ftpd.conf  파일 없음" >> $CREATE_FILE 2>&1
    echo " " >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/vsftpd/vsftpd.conf ]
 then
   echo "② /etc/vsftpd/vsftpd.conf 파일 " >> $CREATE_FILE 2>&1
   cat /etc/vsftpd/vsftpd.conf | grep -i "umask" >> $CREATE_FILE 2>&1
 else
   echo "② /etc/vsftpd/vsftpd.conf 파일 " >> $CREATE_FILE 2>&1
   echo "/etc/vsftpd/vsftpd.conf 파일 없음 " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/proftpd.conf ]
 then
   echo "③ /etc/proftpd.conf 파일 " >> $CREATE_FILE 2>&1
   cat /etc/proftpd.conf | grep -i "umask" >> $CREATE_FILE 2>&1
 else
   echo "③ /etc/proftpd.conf 파일 " >> $CREATE_FILE 2>&1
   echo "/etc/proftpd.conf 파일 없음 " >> $CREATE_FILE 2>&1
fi
else
  echo "☞ ftp 서비스 비 실행중 " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


echo " " > ftp2.txt

if [ -f /etc/vsftpd/vsftpd.conf ]
  then
    if [ `cat /etc/vsftpd/vsftpd.conf | grep -i ".*umask.*077.*" | grep -v "#" | wc -l` -eq 0 ]
      then
        echo "● 5.02 결과 : 취약" >> ftp2.txt
      else
        echo "● 5.02 결과 : 양호" >> ftp2.txt
    fi
fi

if [ -f /etc/vsftpd/vsftpd.conf ]
  then
    if [ `cat /etc/vsftpd/vsftpd.conf | grep -i ".*umask.*077.*" | grep -v "#" | wc -l` -eq 0 ]
      then
        echo "● 5.02 결과 : 취약" >> ftp2.txt
      else
        echo "● 5.02 결과 : 양호" >> ftp2.txt
    fi
fi

if [ -f /etc/proftpd.conf ]
 then
   if [ `cat /etc/proftpd.conf | grep -i ".*umask.*077.*" | grep -v "#" | wc -l` -eq 0 ]
     then
        echo "● 5.02 결과 : 취약" >> ftp2.txt
     else
        echo "● 5.02 결과 : 양호" >> ftp2.txt
   fi
fi

if [ -f /etc/ftpd.conf ]
  then
   if [ `cat /etc/ftpd.conf | grep -i '.*umask.*077.*' | grep -v '#'|wc -l` -eq 0 ]
      then
           echo "● 5.02 결과 : 취약" >> ftp2.txt
      else
           echo "● 5.02 결과 : 양호" >> ftp2.txt
   fi
fi

if [ `cat ftpps.txt | grep ftp | grep -v grep | wc -l` -gt 0 ]
then

  if [ `cat ftp2.txt | grep "양호" | wc -l` -gt 0 ]
   then
    echo "● 5.02 결과 : 양호" >> $CREATE_FILE 2>&1
   else
    echo "● 5.02 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

else
 echo "● 5.02 결과 : 양호" >> $CREATE_FILE 2>&1
fi

rm -rf ftp2.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.03 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.03. Anonymous FTP 제한 ###############################"
echo "############################ 5.주요 응용 설정 - 5.03. Anonymous FTP 제한 ###############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : ftp 를 사용하지 않거나, ftp 사용시 /etc/passwd 파일에 ftp 계정이 존재하지 않을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `cat ftpps.txt | grep ^ftp | grep -v grep | wc -l` -gt 0 ]
then
  if [ -f /etc/passwd ]
  then
    cat /etc/passwd | grep "^ftp" >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다. " >> $CREATE_FILE 2>&1
  fi
else
 echo "ftp 서비스가 비실행중입니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ `cat ftpps.txt | grep ^ftp | grep -v grep | wc -l` -gt 0 ]
then
  if [ `grep -v "^ *#" /etc/passwd | grep "ftp" | egrep -v "false|nologin|null|halt|sync|shutdown" | wc -l` -gt 0 ]
   then
     echo "● 5.03 결과 : 취약" >> $CREATE_FILE 2>&1
   else
     echo "● 5.03 결과 : 양호" >> $CREATE_FILE 2>&1
  fi
else
 echo "● 5.03 결과 : 양호" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.04 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.04. SNMP 서비스 설정 #################################"
echo "############################ 5.주요 응용 설정 - 5.04. SNMP 서비스 설정 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : SNMP 서비스를 사용하지 않거나 Community String이 public, private 이 아닐 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① SNMP 서비스 여부 " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "SNMP가 비실행중입니다. "  >> $CREATE_FILE 2>&1
  else
    ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
ls -al /etc/rc*.d/* | grep -i snmp | grep "/S" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "② /etc/snmp/snmpd.conf 파일 " >> $CREATE_FILE 2>&1
if [ -f /etc/snmp/snmpd.conf ]
        then
           grep -v '^ *#' /etc/snmp/snmpd.conf | egrep -i "public|private" | egrep -v "group|trap" >> $CREATE_FILE 2>&1
        else
          echo " /etc/snmp/snmpd.conf 파일이 존재하지 않음 " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "● 5.04 결과 : 양호" >> $CREATE_FILE 2>&1
  else
   if [ -f /etc/snmp/snmpd.conf ]
    then
      if [ `cat /etc/snmp/snmpd.conf | egrep -i "public|private" | grep -v "#" | egrep -v "group|trap" | wc -l ` -eq 0 ]
        then
          echo "● 5.04 결과 : 양호" >> $CREATE_FILE 2>&1
        else
          echo "● 5.04 결과 : 취약" >> $CREATE_FILE 2>&1
      fi
    else
     echo "● 5.04 결과 : 미점검" >> $CREATE_FILE 2>&1
   fi
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.05 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.05. SMTP Abuse 방지 ##################################"
echo "############################ 5.주요 응용 설정 - 5.05. SMTP Abuse 방지 ##################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : SMTP 서비스를 사용하지 않거나 noexpn, novrfy 옵션이 설정되어 있을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
 else
  ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
ls -al /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "② /etc/mail/sendmail.cf 파일의 옵션 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
  then
    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
  else
    echo "/etc/mail/sendmail.cf 파일 없음" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "● 5.05 결과 : 양호" >> $CREATE_FILE 2>&1
  else
     if [ -f /etc/mail/sendmail.cf ]
      then
      if [ `cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -i "noexpn" | grep -i "novrfy" |grep -v "#" |wc -l ` -eq 1 ]
       then
         echo "● 5.05 결과 : 양호" >> $CREATE_FILE 2>&1
       else
         echo "● 5.05 결과 : 취약" >> $CREATE_FILE 2>&1
      fi
      else
        echo "● 5.05 결과 : 미점검" >> $CREATE_FILE 2>&1
     fi
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1







echo "5.06 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 5.06. 일반사용자의 Sendmail 실행 방지 ##################"
echo "############################ 3.네트워크 서비스 - 5.06. 일반사용자의 Sendmail 실행 방지 ##################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : SMTP 서비스를 사용하지 않거나 restrictqrun 옵션이 설정되어 있을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
 else
  ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
ls -al /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "② /etc/mail/sendmail.cf 파일의 옵션 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
  then
    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
  else
    echo "/etc/mail/sendmail.cf 파일 없음" >> $CREATE_FILE 2>&1
fi



echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "● 5.06 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    if [ -f /etc/mail/sendmail.cf ]
     then
     if [ `cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -i "restrictqrun" | grep -v "#" |wc -l ` -eq 1 ]
       then
         echo "● 5.06 결과 : 양호" >> $CREATE_FILE 2>&1
       else
         echo "● 5.06 결과 : 취약" >> $CREATE_FILE 2>&1
     fi
     else
      echo "● 5.06 결과  : 미점검" >> $CREATE_FILE 2>&1
    fi
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "5.07 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.7 Sendmail 버전 점검 #################################"
echo "############################ 5.주요 응용 설정 - 5.7 Sendmail 버전 점검 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : sendmail 버전이 8.14.4 이상이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "☞ Sendmail 서비스를 사용하지 않습니다." >> $CREATE_FILE 2>&1
 else
  ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "② sendmail 버전확인" >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
   then
     grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ >> $CREATE_FILE 2>&1
   else
     echo "☞ /etc/mail/sendmail.cf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "● 5.07 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    if [ -f /etc/mail/sendmail.cf ]
     then
     if [ `grep -v '^ *#' /etc/mail/sendmail.cf | egrep "DZ8.13.8|DZ8.14.0|DZ8.14.1|DZ8.14.2|DZ8.14.3|DZ8.14.4" | wc -l ` -eq 1 ]
       then
         echo "● 5.07 결과 : 양호" >> $CREATE_FILE 2>&1
       else
         echo "● 5.07 결과 : 취약" >> $CREATE_FILE 2>&1
     fi
     else
      echo "● 5.07 결과 : 미점검" >> $CREATE_FILE 2>&1
     fi
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.07 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "5.08 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 5.08. DNS Zone Transfer 설정 ###########################"
echo "############################ 3.네트워크 서비스 - 5.08. DNS Zone Transfer 설정 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : DNS 서비스를 사용하지 않거나 Zone Transfer 가 제한되어 있을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① DNS 프로세스 확인 " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "DNS가 비실행중입니다." >> $CREATE_FILE 2>&1
  else
    ps -ef | grep named | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
ls -al /etc/rc*.d/* | grep -i named | grep "/S" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "② /etc/named.conf 파일의 allow-transfer 확인" >> $CREATE_FILE 2>&1
   if [ -f /etc/named.conf ]
     then
      cat /etc/named.conf | grep 'allow-transfer' >> $CREATE_FILE 2>&1
     else
      echo "/etc/named.conf 파일 없음" >> $CREATE_FILE 2>&1
   fi

echo " " >> $CREATE_FILE 2>&1

echo "③ /etc/named.boot 파일의 xfrnets 확인" >> $CREATE_FILE 2>&1
   if [ -f /etc/named.boot ]
     then
       cat /etc/named.boot | grep "\xfrnets" >> $CREATE_FILE 2>&1
     else
       echo "/etc/named.boot 파일 없음" >> $CREATE_FILE 2>&1
   fi

echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "● 5.08 결과 : 양호" >> $CREATE_FILE 2>&1
  else
     if [ -f /etc/named.conf ]
       then
         if [ `cat /etc/named.conf | grep "\allow-transfer.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "#" | wc -l` -eq 0 ]
            then
               echo "● 5.08 결과 : 취약" >> $CREATE_FILE 2>&1
            else
               echo "● 5.08 결과 : 양호" >> $CREATE_FILE 2>&1
          fi
        else
          if [ -f /etc/named.boot ]
           then
             if [ `cat /etc/named.boot | grep "\xfrnets.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "#" | wc -l` -eq 0 ]
            then
               echo "● 5.08 결과 : 취약" >> $CREATE_FILE 2>&1
            else
               echo "● 5.08 결과 : 양호" >> $CREATE_FILE 2>&1
            fi
           else
              echo "● 5.08 결과 : 미점검" >> $CREATE_FILE 2>&1
          fi

     fi
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "5.09 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.9 DNS 보안 버전 패치 #################################"
echo "############################ 5.주요 응용 설정 - 5.9 DNS 보안 버전 패치 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : DNS 서비스를 사용이 불필요한 경우에 중지를 권고함."                                            >> $CREATE_FILE 2>&1
echo "          BIND 8 버전에 대한 보안 및 시스템 업데이트 지원이 2007.8.27부터 중단됨에 따라 BIND 9 버전으로의 업그레이드를 권고함" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
DNSPR=`ps -ef | grep named | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`
DNSPR=`echo $DNSPR | awk '{print $1}'`
if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]
 then
  if [ -f $DNSPR ]
   then
    echo "BIND 버전 확인" >> $CREATE_FILE 2>&1
    echo "--------------" >> $CREATE_FILE 2>&1
    $DNSPR -v | grep BIND >> $CREATE_FILE 2>&1
   else
    echo "☞ $DNSPR 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi
 else
  echo "☞ DNS 서비스를 사용하지 않습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
    then
        echo "● 5.09 결과 : 양호" >> $CREATE_FILE 2>&1
    else
        echo "● 5.09 결과 : 미점검" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.09 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "5.10 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.10. SWAT 강제공격 방지 #################################"
echo "############################ 5.주요 응용 설정 - 5.10. SWAT 강제공격 방지 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : Inetd 설정파일에 SWAT 서비스가 활성화 되어있지 않을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1

if [ -d /etc/xinetd.d ]
  then
   if [ `ls -alL /etc/xinetd.d | grep "swat" | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | grep swat | awk '{print $9}'`
        do
        if [ `cat $VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           ls -alL /etc/xinetd.d | grep "swat"  >> $CREATE_FILE 2>&1
           cat $VVV | grep -i "disable"   >> $CREATE_FILE 2>&1
           echo "● 5.10 결과 : 취약  " >> $CREATE_FILE 2>&1
          else
           echo "● 5.10 결과 : 양호  " >> $CREATE_FILE 2>&1
        fi
       done
    else
      echo "● 5.10 결과 : 양호  " >> $CREATE_FILE 2>&1
   fi
 else
   if [ -f /etc/inetd.conf ]
    then
     if [ `cat /etc/inetd.conf | grep -v '^ *#' | grep swat | wc -l` -gt 0 ]
      then
        cat /etc/inetd.conf | grep "swat"  >> $CREATE_FILE 2>&1
        echo "● 5.10 결과 : 취약  " >> $CREATE_FILE 2>&1
      else
        echo "● 5.10 결과 : 양호  " >> $CREATE_FILE 2>&1
      fi
    else
      echo "● 5.10 결과 : 양호  " >> $CREATE_FILE 2>&1
   fi
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.10 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "5.11 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.11 Samba 버전 점검 ###################################"
echo "############################ 5.주요 응용 설정 - 5.11 Samba 버전 점검 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : Samba 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SMBPR=`ps -ef | grep smb | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`

if [ `ps -ef | grep smbd | grep -v grep | wc -l` -gt 0 ]
 then
  ps -ef | grep smbd | grep -v "grep" >> $CREATE_FILE 2>&1
  $SMBPR -V  >> $CREATE_FILE 2>&1
 else
  echo "☞ Samba 서비스를 사용하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep smbd | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "● 5.11 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 5.11 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.11 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "5.12 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.12 SSH 버전 점검 #####################################"
echo "############################ 5.주요 응용 설정 - 5.12 SSH 버전 점검 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : SSH 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있으면 양호(ver 7 이상 양호)" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SSHPR=`ps -ef | grep sshd | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/sshd" | uniq`

echo "① SSH 서비스 확인 " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
  then
   echo "☞ SSH 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
  else
   ps -ef | grep sshd | grep -v grep >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo "② SSH 버전 확인 " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sshd | grep -v "grep" | wc -l`  -eq 0 ]
  then
   echo "☞ SSH 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
  else
   ssh -V >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

ssh -V >> ssh_version.log 2>&1

if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0  ]
   then
     echo "● 5.12 결과 : 양호" >> $CREATE_FILE 2>&1
   else
    if [ `cat ssh_version.log | grep -i "OpenSSH" | wc -l` -gt 0  ]
    then
      if [ `cat ssh_version.log | egrep "7|8" | wc -l` -gt 0  ]
      then
        echo "● 5.12 결과 : 양호" >> $CREATE_FILE 2>&1
      else
        echo "● 5.12 결과 : 취약" >> $CREATE_FILE 2>&1
      fi
    else
    echo "● 5.12 결과 : 미점검" >> $CREATE_FILE 2>&1
    fi
fi

rm -rf ssh_version.log
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.12 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "5.13 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.13. xhost+ 설정 #####################################"
echo "############################ 5.주요 응용 설정 - 5.13. xhost+ 설정 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 자동 실행화일 파일에 “xhost +” 설정이 존재하지 않을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
FILES="/.profile /.cshrc /.kshrc /.login /.bash_profile /.bashrc /.bash_login /.xinitrc /.xsession"

for file in $FILES
  do
    if [ -f $file ]
      then
        echo " cat $file " >> $CREATE_FILE 2>&1
        echo " ------------" >> $CREATE_FILE 2>&1
        grep -v '^ *#' $file | grep "xhost +" >> $CREATE_FILE 2>&1
      else
        echo $file " 파일 없음" >> $CREATE_FILE 2>&1
    fi
done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    if [ -f $dir$file ]
      then
        echo " cat $dir$file " >> $CREATE_FILE 2>&1
        echo "----------------" >> $CREATE_FILE 2>&1
        grep -v '^ *#' $dir$file | grep "xhost +" >> $CREATE_FILE 2>&1
      else
       echo $dir$file " 파일 없음" >> $CREATE_FILE 2>&1
    fi
  done
done

echo " " >> $CREATE_FILE 2>&1

echo " " > xhost.txt
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
FILES="/.profile /.cshrc /.kshrc /.login /.bash_profile /.bashrc /.bash_login /.xinitrc /.xsession"

for file in $FILES
  do
    if [ -f $file ]
      then
        if [ `cat $file | grep "xhost.*+" | grep -v "#" | wc -l` -eq 0 ]
          then
             echo "● 5.13 결과 : 양호" >> xhost.txt
          else
             echo "● 5.13 결과 : 취약" >> xhost.txt
        fi
      else
       echo "  " >> xhost.txt
      echo "● 5.13 결과 : 양호" >> xhost.txt
    fi
done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    if [ -f $dir$file ]
      then
        if [ `cat $dir$file | grep "xhost.*+" | grep -v "#" | wc -l` -eq 0 ]
          then
             echo "● 5.13 결과 : 양호" >> xhost.txt
          else
             echo "● 5.13 결과 : 취약" >> xhost.txt
        fi
      else
       echo "● 5.13 결과 : 양호" >> xhost.txt
    fi
  done
done

if [ `cat xhost.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 5.13 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 5.13 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf xhost.txt


echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.13 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "6.01 START" >> $CREATE_FILE 2>&1
echo "############################ 6.보안패치 - 6.01. 보안패치 #################################################"
echo "############################ 6.보안패치 - 6.01. 보안패치 #################################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준: 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있을 경우에 양호" >> $CREATE_FILE 2>&1
echo "■ 권고" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "알려진 취약점에 대한 보안 패치 및 버그 Fix 사항을 주기적으로 검토하고 적용할 것을 권고함" >> $CREATE_FILE 2>&1
rpm -qa |sort > result_601.txt 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "● 6.01 결과 : 관리권고" >> $CREATE_FILE 2>&1

unset HOMEDIRS
rm -rf ftp_temp
rm -rf ftp2_temp
rm -rf log_temp
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "6.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[ 6.01 상세내역 출력 ]" >> $CREATE_FILE 2>&1
cat result_601.txt >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
rm -rf result_601.txt

echo "************************************************** END *************************************************" >> $CREATE_FILE 2>&1
date >> $CREATE_FILE 2>&1
echo "************************************************** END *************************************************"



echo "***************************************  전체 결과물 파일 생성 시작  ***********************************"

_HOSTNAME=`hostname`
CREATE_FILE_RESULT="LINUX_"${_HOSTNAME}"_"`date +%m%d`"-"`date +%H%M`.txt
echo > $CREATE_FILE_RESULT

echo " "

CREATE_FILE=`hostname`"_before_ini_".txt

awk '/INFO_CHKSTART/,/INFO_CHKEND/' $CREATE_FILE > result_temp.txt 2>&1

cat $CREATE_FILE | grep "END" | awk '{print $1}' > VUL1.txt

for vul in `uniq VUL1.txt`
        do
           awk '/'"$vul"' START/,/'"$vul"' END/' $CREATE_FILE >> result_temp.txt 2>&1
           echo >> result_temp.txt 2>&1
        done

rm -Rf VUL1.txt
echo "***************************************  전체 결과물 파일 생성 끝 **************************************"
echo "**************************************** 진단 결과만 출력 시작 *****************************************"

echo "▶ 진단결과 ◀" > `hostname`_result.txt 2>&1

echo " " >> `hostname`_result.txt 2>&1

hostname >> `hostname`_result.txt 2>&1

echo " " >> `hostname`_result.txt 2>&1
cat result_temp.txt | egrep '양호|취약|미점검|N/A|권고' | grep '●' | sort -u >> `hostname`_result.txt 2>&1

echo " " >> `hostname`_result.txt 2>&1



echo "**************************************** 진단 결과만 출력 끝 *******************************************"
cat result_temp.txt >> $CREATE_FILE_RESULT 2>&1

rm -Rf result_temp.txt
rm -Rf VUL.txt
rm -Rf dtmp
rm -Rf list.txt
rm -Rf result.txt
rm -Rf telnetps.txt ftpps.txt
rm -Rf $CREATE_FILE 2>&1
rm -Rf `hostname`_lsof.txt

mv `hostname`_result.txt "Linux_"`hostname`"_"`date +%m%d`"-"`date +%H%M`_excel_result.txt
#rm -Rf `hostname`_result.txt

rm -Rf `hostname`_result_temp2.txt
rm -Rf `hostname`_before_ini_.txt

echo "☞ 진단작업이 완료되었습니다. 수고하셨습니다!"