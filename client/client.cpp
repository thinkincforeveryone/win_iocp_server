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
		printf("����֤����Ϣ:\n");        
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);   
		printf("֤��: %s\n", line);        free(line);    
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);   
		printf("�䷢��: %s\n", line);    
		free(line);        X509_free(cert);  
	} else       
		printf("��֤����Ϣ��\n");
}

/************���ڱ��ĵ�********************************************
 *************filename: ssl-client.c
 **************purpose: ��ʾ���� OpenSSL ����л��� IP��� SSL ����ͨѶ�ķ��������ǿͻ�������
 ***********************************************************************************/

int main(int argc, char **argv){    
	SOCKET sockfd, len;    
	struct sockaddr_in dest;    
	char buffer[MAXBUF + 1];    
	SSL_CTX *ctx;    SSL *ssl;    
	if (argc != 3) 
	{      
		printf("������ʽ������ȷ�÷����£�\n\t\t%s IP��ַ �˿�\n\t����:\t%s 127.0.0.1 80\n�˳���������ĳ�� IP ��ַ�ķ�����ĳ���˿ڽ������ MAXBUF ���ֽڵ���Ϣ",             argv[0], argv[0]);        
		exit(0);    
	}    
	
	/* SSL ���ʼ�����ο� ssl-server.c ���� */    
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
	
	/* ����һ�� socket ���� tcp ͨ�� */    
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{    
		perror("Socket");     
		exit(errno);  
	}   
	
	printf("socket created\n");   
	

	/* ��ʼ���������ˣ��Է����ĵ�ַ�Ͷ˿���Ϣ */   
	bzero(&dest, sizeof(dest));  
	dest.sin_family = AF_INET;   
	dest.sin_port = htons(atoi(argv[2]));   
	
	if (inet_pton(AF_INET, argv[1], &dest.sin_addr.s_addr) == 0) {
		perror(argv[1]);       
		exit(errno);   
	}   
	printf("address created\n");   
	/* ���ӷ����� */   
	if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) { 
		printf("Connect error:%d", WSAGetLastError());        
		exit(errno);    
	}   
	printf("server connected\n");   
	/* ���� ctx ����һ���µ� SSL */   
	ssl = SSL_new(ctx);   
	SSL_set_fd(ssl, sockfd);   
	/* ���� SSL ���� */   
	if (SSL_connect(ssl) == -1)    
		ERR_print_errors_fp(stderr); 
	else {      
		printf("Connected with %s encryption\n", 
			SSL_get_cipher(ssl));        
		ShowCerts(ssl);   
	}   
		
	
	bzero(buffer, MAXBUF + 1);  
	strcpy_s(buffer,MAXBUF,  "from client->server");   
	
	/* ����Ϣ�������� */  
	len = SSL_write(ssl, buffer, strlen(buffer));  
	if (len < 0)
	{
		char err[256] = { 0 };
		strerror_s(err, errno);
		printf("��Ϣ'%s'����ʧ�ܣ����������%d��������Ϣ��'%s'\n",
			buffer, errno, err);
	}		
	else       
		printf("��Ϣ'%s'���ͳɹ�����������%d���ֽڣ�\n",
			buffer, len); 



	/* ���նԷ�����������Ϣ�������� MAXBUF ���ֽ� */    
	bzero(buffer, MAXBUF + 1);   
	
	/* ���շ�����������Ϣ */    
	len = SSL_read(ssl, buffer, MAXBUF);  
	if (len > 0)      
		printf("������Ϣ�ɹ�:'%s'����%d���ֽڵ�����\n", 
			buffer, len); 
	else {    
		char err[256] = { 0 };
		strerror_s(err, errno);
		printf("��Ϣ����ʧ�ܣ����������%d��������Ϣ��'%s'\n",
			errno, err);        
		goto finish;  
	}  

finish:   
	/* �ر����� */    
	SSL_shutdown(ssl);  
	SSL_free(ssl);  
	close(sockfd);   
	SSL_CTX_free(ctx);  

	return 0;

}