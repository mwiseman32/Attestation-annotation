#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <signal.h>
#include <ctype.h>          
#include <arpa/inet.h>
#include <netdb.h>

#define PORT 20000
#define LENGTH 4096 


void error(const char *msg)
{
	perror(msg);
	exit(1);
}

int main(int argc, char *argv[])
{
	/* Variable Definition */
	int sockfd; 
	int nsockfd;
	char revbuf[LENGTH]; 
	struct sockaddr_in remote_addr;

	/* Get the Socket file descriptor */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		fprintf(stderr, "ERROR: Failed to obtain Socket Descriptor! (errno = %d)\n",errno);
		exit(1);
	}

	/* Fill the socket address struct */
	remote_addr.sin_family = AF_INET; 
	remote_addr.sin_port = htons(PORT); 
	inet_pton(AF_INET, "127.0.0.1", &remote_addr.sin_addr); 
	bzero(&(remote_addr.sin_zero), 8);

	/* Try to connect the remote */
	if (connect(sockfd, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr)) == -1)
	{
		fprintf(stderr, "ERROR: Failed to connect to the host! (errno = %d)\n",errno);
		exit(1);
	}
	else 
		printf("[Client] Connected to server at port %d...ok!\n", PORT);

	/* Send File to Server */
	//if(!fork())
	//{     
		system("chmod +x client.sh ; ./client.sh");
		char* fs_name = "/home/test/Downloads/demo/demo/demo1/clientinfo.txt";
		char sdbuf[LENGTH]; 
		printf("[Client] Sending %s to the Server... \n", fs_name);
		FILE *fs = fopen(fs_name, "r");
		if(fs == NULL)
		{
			printf("[Client] ERROR: File %s not found.\n", fs_name);
			exit(1);
		}

		bzero(sdbuf, LENGTH); 
		int fs_block_sz; 
		while((fs_block_sz = fread(sdbuf, sizeof(char), LENGTH, fs)) > 0)
		{
		    if(send(sockfd, sdbuf, fs_block_sz, 0) < 0)
		    {
		        fprintf(stderr, "ERROR: Failed to send file %s. (errno = %d)\n", fs_name, errno);
		        break;
		    }
		    bzero(sdbuf, LENGTH);
		}
		printf("[Client] Sent File %s to server!\n", fs_name);
	//}
	//printf("[Client] client is creating primary context...wait\n");
	//system("chmod +x script1.sh ; ./script1.sh");
	/* Receive File from Server */
	printf("[Client] Receiveing file from Server and saving it as quote.sh...\n");
	char* fr_name = "/home/test/Downloads/demo/demo/demo1/quote.sh";
	FILE *fr = fopen(fr_name, "a");
	if(fr == NULL)
		printf("[Client] File %s Cannot be opened.\n", fr_name);
	else
	{
		bzero(revbuf, LENGTH); 
		int fr_block_sz = 0;
	    while((fr_block_sz = recv(sockfd, revbuf, LENGTH, 0)) > 0)
	    {
			int write_sz = fwrite(revbuf, sizeof(char), fr_block_sz, fr);
	        if(write_sz < fr_block_sz)
			{
	            error("[Client] File write failed.\n");
	        }
			bzero(revbuf, LENGTH);
			if (fr_block_sz == 0 || fr_block_sz != 512) 
			{
				break;
			}
		}
		if(fr_block_sz < 0)
        {
			if (errno == EAGAIN)
			{
				printf("[Client] recv() timed out.\n");
			}
			else
			{
				fprintf(stderr, "recv() failed due to errno = %d\n", errno);
			}
		}
	    printf("[Client] Received ok from server!\n");
	    fclose(fr);
	}
	printf("[Client] generating quote on client!\n");
	system("chmod +x quote.sh ; ./quote.sh");
	printf("[Client] generated quote and resultant files on client!\n");
	printf("[Client] transfering quote and resultant files to server!\n");
	printf("[Client] transfering quote file to server!\n");

	char* fs1_name = "/home/test/Downloads/demo/demo/demo1/quote.out";
		char sdbuf1[LENGTH]; 
		printf("[Client] Sending %s to the Server... \n", fs1_name);
		FILE *fs1 = fopen(fs1_name, "r");
		if(fs1 == NULL)
		{
			printf("[Client] ERROR: File %s not found.\n", fs1_name);
			exit(1);
		}

		bzero(sdbuf1, LENGTH); 
		int fs1_block_sz; 
		while((fs1_block_sz = fread(sdbuf1, sizeof(char), LENGTH, fs1)) > 0)
		{
		    if(send(sockfd, sdbuf1, fs1_block_sz, 0) < 0)
		    {
		        fprintf(stderr, "ERROR: Failed to send file %s. (errno = %d)\n", fs1_name, errno);
		        break;
		    }
		    bzero(sdbuf1, LENGTH);
		}
		printf("[Client] Sent File %s to server!\n", fs1_name);

	printf("[Client] transfering pcrs.out file to server!\n");

		char* fs2_name = "/home/test/Downloads/demo/demo/demo1/pcrs.out";
		char sdbuf2[LENGTH]; 
		printf("[Client] Sending %s to the Server... \n", fs2_name);
		FILE *fs2 = fopen(fs2_name, "r");
		if(fs2 == NULL)
		{
			printf("[Client] ERROR: File %s not found.\n", fs2_name);
			exit(1);
		}

		bzero(sdbuf2, LENGTH); 
		int fs2_block_sz; 
		while((fs2_block_sz = fread(sdbuf2, sizeof(char), LENGTH, fs2)) > 0)
		{
		    if(send(sockfd, sdbuf2, fs2_block_sz, 0) < 0)
		    {
		        fprintf(stderr, "ERROR: Failed to send file %s. (errno = %d)\n", fs2_name, errno);
		        break;
		    }
		    bzero(sdbuf2, LENGTH);
		}
		printf("[Client] Sent File %s to server!\n", fs2_name);


	printf("[Client] transfering sig.out file to server!\n");

		char* fs3_name = "/home/test/Downloads/demo/demo/demo1/sig.out";
		char sdbuf3[LENGTH]; 
		printf("[Client] Sending %s to the Server... \n", fs3_name);
		FILE *fs3 = fopen(fs3_name, "r");
		if(fs3 == NULL)
		{
			printf("[Client] ERROR: File %s not found.\n", fs3_name);
			exit(1);
		}

		bzero(sdbuf3, LENGTH); 
		int fs3_block_sz; 
		while((fs3_block_sz = fread(sdbuf3, sizeof(char), LENGTH, fs3)) > 0)
		{
		    if(send(sockfd, sdbuf3, fs3_block_sz, 0) < 0)
		    {
		        fprintf(stderr, "ERROR: Failed to send file %s. (errno = %d)\n", fs3_name, errno);
		        break;
		    }
		    bzero(sdbuf3, LENGTH);
		}
		printf("[Client] Sent File %s to server!\n", fs3_name);


	printf("[Client] transfering akpub.pem file to server!\n");

		char* fs4_name = "/home/test/Downloads/demo/demo/demo1/akpub.pem";
		char sdbuf4[LENGTH]; 
		printf("[Client] Sending %s to the Server... \n", fs4_name);
		FILE *fs4 = fopen(fs4_name, "r");
		if(fs4 == NULL)
		{
			printf("[Client] ERROR: File %s not found.\n", fs4_name);
			exit(1);
		}

		bzero(sdbuf4, LENGTH); 
		int fs4_block_sz; 
		while((fs4_block_sz = fread(sdbuf4, sizeof(char), LENGTH, fs4)) > 0)
		{
		    if(send(sockfd, sdbuf4, fs4_block_sz, 0) < 0)
		    {
		        fprintf(stderr, "ERROR: Failed to send file %s. (errno = %d)\n", fs4_name, errno);
		        break;
		    }
		    bzero(sdbuf4, LENGTH);
		}
		printf("[Client] Sent File %s to server!\n", fs4_name);


	printf("[Client] transfering result file to server!\n");

		char* fs5_name = "/home/test/Downloads/demo/demo/demo1/result";
		char sdbuf5[LENGTH]; 
		printf("[Client] Sending %s to the Server... \n", fs5_name);
		FILE *fs5 = fopen(fs5_name, "r");
		if(fs5 == NULL)
		{
			printf("[Client] ERROR: File %s not found.\n", fs5_name);
			exit(1);
		}

		bzero(sdbuf5, LENGTH); 
		int fs5_block_sz; 
		while((fs5_block_sz = fread(sdbuf5, sizeof(char), LENGTH, fs5)) > 0)
		{
		    if(send(sockfd, sdbuf5, fs5_block_sz, 0) < 0)
		    {
		        fprintf(stderr, "ERROR: Failed to send file %s. (errno = %d)\n", fs5_name, errno);
		        break;
		    }
		    bzero(sdbuf5, LENGTH);
		}
		printf("[Client] Sent File %s to server!\n", fs5_name);

	close (sockfd);
	printf("[Client] Connection lost.\n");
	return (0);
}
