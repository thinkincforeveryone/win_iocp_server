#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <Windows.h>
#include <WinSock2.h>
#include <MSWSock.h>
#include <WS2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "Crypt32.lib")
#define bzero ZeroMemory
#define close closesocket

#define MAXBUF 1024

void ShowCerts(SSL * ssl)
{    
	X509 *cert;    
	char *line;    
	cert = SSL_get_peer_certificate(ssl);    
	if (cert != NULL) 
	{        
		printf("数字证书信息:\n");        
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);   
		printf("证书: %s\n", line);        free(line);    
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);   
		printf("颁发者: %s\n", line);    
		free(line);        X509_free(cert);  
	} else       
		printf("无证书信息！\n");
}

/************关于本文档********************************************
 *************filename: ssl-client.c
 **************purpose: 演示利用 OpenSSL 库进行基于 IP层的 SSL 加密通讯的方法，这是客户端例子
 ***********************************************************************************/

int main(int argc, char **argv){    
	SOCKET sockfd, len;    
	struct sockaddr_in dest;    
	char buffer[MAXBUF + 1];    
	SSL_CTX *ctx;    SSL *ssl;    
	if (argc != 3) 
	{      
		printf("参数格式错误！正确用法如下：\n\t\t%s IP地址 端口\n\t比如:\t%s 127.0.0.1 80\n此程序用来从某个 IP 地址的服务器某个端口接收最多 MAXBUF 个字节的消息",             argv[0], argv[0]);        
		exit(0);    
	}    
	
	/* SSL 库初始化，参看 ssl-server.c 代码 */    
	SSL_library_init();    
	OpenSSL_add_all_algorithms();    
	SSL_load_error_strings();   
	//	  SSL_CTX_new(SSLv23_server_method());
	ctx = SSL_CTX_new(SSLv23_client_method());    
	if (ctx == NULL) {   
		ERR_print_errors_fp(stdout);     
		exit(1);   
	}    

	WSADATA wsaData;
	int iResult = 0;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"Error at WSAStartup()\n");
		return 1;
	}
	
	/* 创建一个 socket 用于 tcp 通信 */    
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{    
		perror("Socket");     
		exit(errno);  
	}   
	
	printf("socket created\n");   
	

	/* 初始化服务器端（对方）的地址和端口信息 */   
	bzero(&dest, sizeof(dest));  
	dest.sin_family = AF_INET;   
	dest.sin_port = htons(atoi(argv[2]));   
	
	if (inet_pton(AF_INET, argv[1], &dest.sin_addr.s_addr) == 0) {
		perror(argv[1]);       
		exit(errno);   
	}   
	printf("address created\n");   
	/* 连接服务器 */   
	if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) { 
		printf("Connect error:%d", WSAGetLastError());        
		exit(errno);    
	}   
	printf("server connected\n");   
	/* 基于 ctx 产生一个新的 SSL */   
	ssl = SSL_new(ctx);   
	SSL_set_fd(ssl, sockfd);   
	/* 建立 SSL 连接 */   
	if (SSL_connect(ssl) == -1)    
		ERR_print_errors_fp(stderr); 
	else {      
		printf("Connected with %s encryption\n", 
			SSL_get_cipher(ssl));        
		ShowCerts(ssl);   
	}   
		
	
	bzero(buffer, MAXBUF + 1);  
	strcpy_s(buffer,MAXBUF,  "from client->server");   
	
	/* 发消息给服务器 */  
	len = SSL_write(ssl, buffer, strlen(buffer));  
	if (len < 0)
	{
		char err[256] = { 0 };
		strerror_s(err, errno);
		printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n",
			buffer, errno, err);
	}		
	else       
		printf("消息'%s'发送成功，共发送了%d个字节！\n",
			buffer, len); 



	/* 接收对方发过来的消息，最多接收 MAXBUF 个字节 */    
	bzero(buffer, MAXBUF + 1);   
	
	/* 接收服务器来的消息 */    
	len = SSL_read(ssl, buffer, MAXBUF);  
	if (len > 0)      
		printf("接收消息成功:'%s'，共%d个字节的数据\n", 
			buffer, len); 
	else {    
		char err[256] = { 0 };
		strerror_s(err, errno);
		printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",
			errno, err);        
		goto finish;  
	}  

finish:   
	/* 关闭连接 */    
	SSL_shutdown(ssl);  
	SSL_free(ssl);  
	close(sockfd);   
	SSL_CTX_free(ctx);  

	return 0;

}