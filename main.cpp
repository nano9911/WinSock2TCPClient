#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")

#define RECV_BUFLEN 512
#define SEND_BUFLEN 128

SOCKET CreateSocket(struct addrinfo* result);

int __cdecl main(int argc, char *argv[])
{
	if (argc != 3) {
		printf("Usage: %s server-name port-number\n", argv[0]);
		ExitProcess(1);
	}

	WSADATA wsadata;
	/* Normal BSD sockets arguments, res / hints (ptr is defined in
	CreateSocket function) */
	struct addrinfo* result = NULL,
		hints;
	/* The socket variable we will use to specify our socket */
	SOCKET ConnectSocket = INVALID_SOCKET;
	int iResult = 0, iSendResult = 0, iReceiveResult = 0;
	int recvbuflen = RECV_BUFLEN;
	int sendbuflen = SEND_BUFLEN;
	
	/* Sending and receiving buffers which is of type char, and it's
	size from preproccesed variables */
	char sendbuf[SEND_BUFLEN],
		recvbuf[RECV_BUFLEN];

	/* start WSA service to create, edit and sockets use in windows */
	iResult = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		ExitProcess(1);
	}

	/* Filling the required info into hints to use it in getaddrinfo()
	as our chosen options */
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;			/* Unspecified: IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;		/* Stream Socket (TCP) */
	hints.ai_protocol = IPPROTO_TCP;		/* IP Network Layer Protocol */

	/*
	*	getaddrinfo() return a linked list of addrinfo structs
	*	which we will test to create our socket and connect to
	*	the target server.
	*/
	iResult = getaddrinfo(argv[1], argv[2], &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		ExitProcess(1);
	}

	ConnectSocket = CreateSocket(result);

	freeaddrinfo(result);

	do {
		/* Flush the receiveing and sending buffers to insure quality */
		ZeroMemory(recvbuf, recvbuflen);
		ZeroMemory(sendbuf, sendbuflen);

		/* instead of using ZeroMemory which is only in windows, you can use
		memset() c function and fill the buffers with NULL '\0' values */
//		memset(&recvbuf, '\0', recvbuflen);
//		memset(&sendbuf, '\0', sendbuflen);

		/* take user input using fgets to keep take input until new line detected
		as input from STDIN*/
		fgets(sendbuf, SEND_BUFLEN, stdin);
		/* you can use scanf_s which is also secure, but I didn't really test it */
//		scanf_s("%[^\n]%*c", sendbuf, sendbuflen);

		/* if the sending buffer after getting user input still empty, then break
		the loop and close the connection with server */
		if ((int)strlen(sendbuf) == 0)	{
			break;
		}

		/* send() use the data in send buffer as the message to send, and returns the
		count of data sent in bytes. */
		iSendResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
		if (iSendResult == SOCKET_ERROR) {
			printf("send failed: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
			WSACleanup();
			ExitProcess(1);
		}

		printf("Message sent: %s\tBytes sent: %d\n", sendbuf, iSendResult);

		/* recv() saves the received message in the received buffer and return the sizeof it in bytes */
		iReceiveResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);

		/* if the received message is an empty message or recv() returns an empty string
		this means the connection is closed or the there's something wrong.
		So break the loop, clean up WSA services and close the socket.  */
		if (iReceiveResult > 0) {
			printf("Message received: %s\tBytes received: %d\n", recvbuf, iReceiveResult);
		}
		else if (iReceiveResult == 0) {
			printf("Empty Message Received\nConnection Closing...\n\n");
		}
		else	{
			printf("recv failed: %d", WSAGetLastError());
		}

	} while (iReceiveResult > 0);

	/* start the procedure of closing the connection with client by shuting down both sending and recieving,
	then close the socket safely, and exit the thread with last value of exit code. */
	iResult = shutdown(ConnectSocket, SD_BOTH);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed: %d", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		ExitProcess(1);
	}

	closesocket(ConnectSocket);
	WSACleanup();

	ExitProcess(0);
}

/*
	Our function to handle the tests of the linked lists returned
	by getaddrinfo() (* res), then if a member of the list worked
	it will be returned type (SOCKET) to use it.
*/
SOCKET CreateSocket(struct addrinfo* result) {
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo* ptr = NULL;
	int iResult = 0;

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		/* Create a socket with the given info from the current value of (* ptr) */
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			/* failure in socket() is not critical and we can test the next one */
			printf("Error at socket(): %ld\n", WSAGetLastError());
			continue;
		}

		/* We don't need to use the SO_REUSEADDR option, because the client port number
		is not a target for DOS Attacks, and it's chosen randomly from the OS */

		/* Connect to the target server from the address given in ai_addr from addrinfo struct */
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			/* failure in connect() is not critical and we can test the next one */
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}

		break;
	}

	/* if ptr == NULL this means the for loop ended without creating a valid socket
	or failed to bind any of the created sockets to the required port */
	if (ptr == NULL) {
		printf("$ Couldn't open a socket\n");
		WSACleanup();
		ExitProcess(1);
	}

	return ConnectSocket;
}