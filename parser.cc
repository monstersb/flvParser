#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <arpa/inet.h>

using namespace std;

#define RTMP_PACKET_TYPE_INFO	0x12
#define RTMP_PACKET_TYPE_AUDIO	0x08
#define RTMP_PACKET_TYPE_VIDEO	0x09

#pragma pack(1)

char const *tagtype[] = { "", "RTMP_PACKET_TYPE_CHUNK_SIZE", "", 
	"RTMP_PACKET_TYPE_BYTES_READ_REPORT",
	"RTMP_PACKET_TYPE_CONTROL", 
	"RTMP_PACKET_TYPE_SERVER_BW", 
	"RTMP_PACKET_TYPE_CLIENT_BW", "",
	"RTMP_PACKET_TYPE_AUDIO", 
	"RTMP_PACKET_TYPE_VIDEO", "", "", "", "", "", 
	"RTMP_PACKET_TYPE_FLEX_STREAM_SEND",
	"RTMP_PACKET_TYPE_FLEX_SHARED_OBJECT", 
	"RTMP_PACKET_TYPE_FLEX_MESSAGE", 
	"RTMP_PACKET_TYPE_INFO", 
	"RTMP_PACKET_TYPE_SHARED_OBJECT", 
	"RTMP_PACKET_TYPE_INVOKE", "", 
	"RTMP_PACKET_TYPE_FLASH_VIDEO"
};



struct flvheader
{
	char signature[3];
	char version;
	char type;
	int dataoffset;
};

struct flvtagheader
{
	char type;
	unsigned char datalength[3];
	unsigned char timestamp[3];
	char timestamp1;
	unsigned char streamid[3];
};

struct flvtag
{
	int size;
	flvtagheader hdr;
	char *data;
};

int parser(const char* fname);
int filesize(int fd);
int gettag(int fd);
char *infoparser(char *data, int len);

int main(int argc, char *argv[])
{
	int opt;
	int method = 0;
	int iret = 0;
	char *fname = NULL;
	while ((opt = getopt(argc, argv, "atf:")) != EOF)
	{
		switch (opt)
		{
		case 'a':
			method |= 0x00000001;
			break;
		case 't':
			method |= 0x00000002;
			break;
		case 'f':
			fname = new char[strlen(optarg) + 1];
			strcpy(fname ,optarg);
			break;
		default:
			cout << "usage:" << endl;
			cout << "\t" << argv[0] << " [-a|-t] -f xx.flv" << endl;
			iret = -1;;;;
		}
	}
	if (fname == NULL || (method != 1 && method != 2))
	{
		cout << "usage:" << endl;
		cout << "\t" << argv[0] << " [-a|-t] -f xx.flv" << endl;
	}
	if (method == 1)
	{
		iret = parser(fname);
	}
	else if (method == 2)
	{
	}
	if (fname)
	{
		delete fname;
	}
	return iret;
}

int parser(const char* fname)
{
	int fd;
	fd = open(fname, O_RDONLY);
	if (fd == -1)
	{
		cerr << "can not open file(" << strerror(errno) << ")" << endl;
		return -1;
	}
	printf("file size : %d\n", filesize(fd));
	int readsize;
	flvheader hdr;
	bzero(&hdr, sizeof(hdr));
	readsize = read(fd, &hdr, sizeof(hdr));
	if (readsize != sizeof(hdr) || hdr.signature[0] != 'F' || hdr.signature[1] != 'L' || hdr.signature[2] != 'V')
	{
		cerr << "bad file" << endl;
		close(fd);
		return -1;
	}
	cout << "header:" << endl;
	printf("\t%-8s: 0x%02X\n", "version", hdr.version);
	printf("\t%-8s: 0x%02X\n", "type", hdr.type);
	printf("\t\tvideo : %s\n", hdr.type & 0x01 ? "true" : "false");
	printf("\t\taudio : %s\n", hdr.type & 0x03 ? "true" : "false");
	printf("\t%-8s: %d\n", "offset", ntohl(hdr.dataoffset));
	lseek(fd, ntohl(hdr.dataoffset) + 4, SEEK_SET);
	while (!gettag(fd))
	{
		lseek(fd, 4, SEEK_CUR);
	}
	close(fd);
	return 0;
}

int filesize(int fd)
{
	int cur, size;
	cur = lseek(fd, 0, SEEK_CUR);
	lseek(fd, 0, SEEK_END);
	size = lseek(fd, 0, SEEK_CUR);
	lseek(fd, cur, SEEK_SET);
	return size;
}

int gettag(int fd)
{
	int size;
	int readsize;
	flvtag tag;
	readsize = read(fd, &(tag.hdr), sizeof(tag.hdr));
	if (readsize != sizeof(tag.hdr))
	{
		return -1;
	}
	printf("tag type    : 0x%0X (%s)\n", tag.hdr.type, tagtype[tag.hdr.type]);
	int datalen;
	datalen = (int)tag.hdr.datalength[0] << 16 | (int)tag.hdr.datalength[1] << 8 | (int)tag.hdr.datalength[2];
	printf("data length : %d\n", datalen);
	printf("timestamp   : %d\n", (int)tag.hdr.timestamp[0] << 16 | (int)tag.hdr.timestamp[1] << 8 | (int)tag.hdr.timestamp[2]);
	printf("streamid    : %d\n", (int)tag.hdr.streamid[0] << 16 | (int)tag.hdr.streamid[1] << 8 | (int)tag.hdr.streamid[2]);
	tag.data = new char[datalen];
	readsize = read(fd, tag.data, datalen);
	if (readsize != datalen)
	{
		return -1;
	}
	switch (tag.hdr.type)
	{
	case 0x12:
		infoparser(tag.hdr.data, datalen);
	}
	cout << endl;
	return 0;
}

char *parserarray(char *data, int layer)
{
	char *p = data;
	double number;
	char tstr[1024];
	int i = 0;
	if (*p == AMF_OBJECT)
	{
		p = p + 1;
		while (!(p[0] == '\x00' && p[1] == '\x00' && p[2] == '\x09'))
		{
			int namelen;
			namelen = ntohs(*(uint16_t*)(p));
			for (i = 0; i < layer; i++)
			{
				printf("\t");
			}
			memcpy(tstr, p + 2, namelen);
			tstr[namelen] = '\0';
			printf("\t%s : ", tstr);
			p = p + 2 + namelen;
			switch (*p)
			{
			case AMF_NUMBER:
				number = AMF_DecodeNumber(p + 1);
				printf("%lf\n", number);
				p = p + 9;
				break;
			case AMF_BOOLEAN:
				printf(*(p + 1) ? "TRUE\n" : "FALSE\n");
				p = p + 2;
				break;
			case AMF_STRING:
				printf("%s\n", p + 3);
				p = p + 1 + 2 + ntohs(*(uint16_t*)(p + 1));
				break;
			case AMF_NULL:
				printf("NULL\n");
				p = p + 1;
				break;
			case AMF_UNDEFINED:
				printf("Undefined\n");
				p = p + 1;
				break;
			case AMF_ECMA_ARRAY:
			case AMF_OBJECT:
				printf("\n");
				p = parserarray(p, layer + 1);
				break;
			}
		}
		p = p + 3;
	}
	else if (*p == AMF_ECMA_ARRAY)
	{
		int len;
		p = p + 1;
		len = ntohl(*(uint32_t*)(p));
		p = p + 4;
		while (!(p[0] == '\x00' && p[1] == '\x00' && p[2] == '\x09') && len--)
		{
			int namelen;
			namelen = ntohs(*(uint16_t*)(p));
			for (i = 0; i < layer; i++)
			{
				printf("\t");
			}
			memcpy(tstr, p + 2, namelen);
			tstr[namelen] = '\0';
			printf("\t%s : ", tstr);
			p = p + 2 + namelen;
			switch (*p)
			{
			case AMF_NUMBER:
				number = AMF_DecodeNumber(p + 1);
				printf("%lf\n", number);
				p = p + 9;
				break;
			case AMF_BOOLEAN:
				printf(*(p + 1) ? "TRUE\n" : "FALSE\n");
				p = p + 2;
				break;
			case AMF_STRING:
				printf("%s\n", p + 3);
				p = p + 1 + 2 + ntohs(*(uint16_t*)(p + 1));
				break;
			case AMF_NULL:
				printf("NULL\n");
				p = p + 1;
				break;
			case AMF_UNDEFINED:
				printf("Undefined\n");
				p = p + 1;
				break;
			case AMF_ECMA_ARRAY:
			case AMF_OBJECT:
				printf("\n");
				p = parserarray(p, layer + 1);
				break;
			}
		}
		p = p + 3;
	}
	return p;
}

char *infoparser(char *data, int len)
{
	char *p = data;
	while (p - data < len)
	{
		switch (*p)
		{
		case AMF_NUMBER:
			p = p + 9;
			break;
		case AMF_BOOLEAN:
			p = p + 2;
			break;
		case AMF_STRING:
			printf("%s\n", p + 3);
			p = p + 1 + 2 + ntohs(*(uint16_t*)(p + 1));
			break;
		case AMF_UNDEFINED:
			printf("Undefined\n");
			p = p + 1;
			break;
		case AMF_OBJECT:
		case AMF_ECMA_ARRAY:
			p = parserarray(p, 1);
			break;
		case AMF_NULL:
			p = p + 1;
			break;
		}
	}
	printf("-----------------------------------------------------------------------------------\n");
	return 0;
	}
