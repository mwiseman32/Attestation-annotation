/*
 * tlv_dump
 * 
 * 
 * Copyright (C) 2018 GE
 * Author:  David Safford <david.safford@ge.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * tlv_dump reads binary tlv data from stdin, parses it, verifies it,
 * and displays the data and the verification to stdout.
 * For each record, the TCG digest is verified against the content, 
 * and the signature (if present) is verified against the public key list.
 * For the entire list, an expected PCR-10 is calculated.
 *
 * usage: tlv_dump [-k key_list_file] [-p hex_pcr_target]
 *
 * Limitations: This currently assumes PCR-10 and all its extends are
 *              sha-1 bank only.
 */
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <asm/byteorder.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/* TCG Top Level TLV Types */
#define IMA_TLV_SEQ 	0
#define IMA_TLV_PCR 	1
#define IMA_TLV_DIGEST 	2
#define IMA_TLV_CONTENT	7

/* TCG Digest Types */
#define IMA_TLV_DIGEST_SHA1	4
#define IMA_TLV_DIGEST_SHA256	8

/* IMA Specific Content Types */
#define IMA_TLV_CONTENT_PATH		0
#define IMA_TLV_CONTENT_DATAHASH	1
#define IMA_TLV_CONTENT_DATASIG		2
#define IMA_TLV_CONTENT_OWNER		3
#define IMA_TLV_CONTENT_GROUP		4
#define IMA_TLV_CONTENT_MODE		5
#define IMA_TLV_CONTENT_TIMESTAMP	6
#define IMA_TLV_CONTENT_LABEL		7

#define	NUM_PCRS 	20
#define DEFAULT_PCR 	10
#define	DATA_SIZE	4096
#define SHA1_HASH_LEN   20
#define MAX_DATA_HASH 	32	/* sha-256 */
#define MAX_DATA_SIG 	256	/* 2048 bit RSA */
#define MAX_TLV 	4096

#define __packed __attribute__((packed))

enum pkey_hash_algo {
       	PKEY_HASH_MD4,
	PKEY_HASH_MD5,
	PKEY_HASH_SHA1,
	PKEY_HASH_RIPE_MD_160,
	PKEY_HASH_SHA256,
	PKEY_HASH_SHA384,
	PKEY_HASH_SHA512,
	PKEY_HASH_SHA224,
	PKEY_HASH__LAST
};

const char *const pkey_hash_algo[PKEY_HASH__LAST] = {
	[PKEY_HASH_MD4]		= "md4",
	[PKEY_HASH_MD5]		= "md5",
	[PKEY_HASH_SHA1]	= "sha1",
	[PKEY_HASH_RIPE_MD_160]	= "rmd160",
	[PKEY_HASH_SHA256]	= "sha256",
	[PKEY_HASH_SHA384]	= "sha384",
	[PKEY_HASH_SHA512]	= "sha512",
	[PKEY_HASH_SHA224]	= "sha224",
};

/*
 * ima signature format
 */
struct signature_v2_hdr {
	uint8_t version;
	uint8_t	hash_algo;
	uint32_t keyid;
	uint16_t sig_size;
       	uint8_t sig[0];
} __packed;

struct RSA_ASN1_template {
	const uint8_t *data;
	size_t size;
};

struct pk_entry {
	struct pk_entry *next;
	uint32_t keyid;
	char name[9];
	RSA *key;
};

struct tlv {
	uint8_t t;
	uint32_t l;
	uint8_t v[MAX_TLV];
};

/*
 * RFC4880 sec 5.2.2.
 */
static const uint8_t RSA_info_MD5[] = {
	0x30, 0x20, 0x30, 0x0C, 0x06, 0x08,
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05,
	0x05, 0x00, 0x04, 0x10
};

static const uint8_t RSA_info_SHA1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
	0x2B, 0x0E, 0x03, 0x02, 0x1A,
	0x05, 0x00, 0x04, 0x14
};

static const uint8_t RSA_info_RIPE_MD_160[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
	0x2B, 0x24, 0x03, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x14
};

static const uint8_t RSA_info_SHA224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
	0x05, 0x00, 0x04, 0x1C
};

static const uint8_t RSA_info_SHA256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x20
};

static const uint8_t RSA_info_SHA384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
	0x05, 0x00, 0x04, 0x30
};

static const uint8_t RSA_info_SHA512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
	0x05, 0x00, 0x04, 0x40
};

const struct RSA_ASN1_template RSA_ASN1_templates[PKEY_HASH__LAST] = {
#define _(X) { RSA_info_##X, sizeof(RSA_info_##X) }
	[PKEY_HASH_MD5]		= _(MD5),
	[PKEY_HASH_SHA1]	= _(SHA1),
	[PKEY_HASH_RIPE_MD_160]	= _(RIPE_MD_160),
	[PKEY_HASH_SHA256]	= _(SHA256),
	[PKEY_HASH_SHA384]	= _(SHA384),
	[PKEY_HASH_SHA512]	= _(SHA512),
	[PKEY_HASH_SHA224]	= _(SHA224),
#undef _
};

static struct pk_entry *public_keys = NULL;
static uint8_t pcrten[MAX_DATA_HASH];
static uint8_t pcrten_target[MAX_DATA_HASH];
static uint8_t content_digest[MAX_DATA_HASH];
static uint8_t content_hash[MAX_DATA_HASH];
static uint8_t data_hash[MAX_DATA_HASH];
static int data_hash_len;
static uint8_t data_sig[MAX_DATA_SIG];
static int data_sig_len;

static RSA *find_keyid(uint32_t keyid)
{
	struct pk_entry *entry;

	for (entry = public_keys; entry != NULL; entry = entry->next) {
		if (entry->keyid == keyid)
			return entry->key;
	}
	return NULL;
}

static int get_hash_algo_from_sig(unsigned char *sig)
{
	uint8_t hashalgo;

	if (sig[0] == 2) {
		hashalgo = ((struct signature_v2_hdr *)sig)->hash_algo;
		if (hashalgo >= PKEY_HASH__LAST)
			return -1;
		return hashalgo;
	} else
		return -1;
}

static int verify_ima_sig(unsigned char *sig, int siglen, 
	       unsigned char *hash, int hashlen)
{
	unsigned char out[1024];
	struct signature_v2_hdr *hdr;
	const struct RSA_ASN1_template *asn1;
	int hash_algo, len;
	RSA *key;

	if (sig[0] != 0x03) {
		fprintf(stderr, "signature not found\n");
		return -1;
	}
	hdr = (struct signature_v2_hdr *)(sig + 1);
	hash_algo = get_hash_algo_from_sig((unsigned char *)hdr);
	if (hash_algo < 0) {
		fprintf(stderr, "Invalid hash algorithm\n");
		return -1;
	}
	if (hashlen <= 0) {
		fprintf(stderr, "Invalid hash length\n");
		return -1;
	}

	key = find_keyid(hdr->keyid);
	if (!key) {
		fprintf(stderr, "unknown keyid: %x\n",
			__be32_to_cpup(&hdr->keyid));
		return -1;
	}

	len = RSA_public_decrypt(siglen - sizeof(*hdr) - 1, (unsigned char *)hdr
				 + sizeof(*hdr), out, key, RSA_PKCS1_PADDING);
	if (len < 0) {
		fprintf(stderr, "RSA_public_decrypt() failed: %d\n", len);
		return 1;
	}

	asn1 = &RSA_ASN1_templates[hdr->hash_algo];

	if (len < asn1->size || memcmp(out, asn1->data, asn1->size)) {
		fprintf(stderr, "verification failed: %d\n", len);
		return -1;
	}

	len -= asn1->size;

	if (len != hashlen || memcmp(out + asn1->size, hash, len)) {
		fprintf(stderr, "verification failed: %d\n", len);
		return -1;
	}

	return 0;
}

static void get_keyid(uint32_t *keyid, char *str, RSA *key)
{
	uint8_t sha1[SHA_DIGEST_LENGTH];
	unsigned char *pkey = NULL;
	int len;

	len = i2d_RSAPublicKey(key, &pkey);

	SHA1(pkey, len, sha1);

	/* sha1[12 - 19] is keyid */
	memcpy(keyid, sha1 + 16, 4);

	free(pkey);
}

static RSA *read_pk(const char *keyfile)
{
	FILE *fp;
	RSA *key = NULL;

	fp = fopen(keyfile, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open keyfile: %s\n", keyfile);
		return NULL;
	}

	key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);

	if (!key)
		fprintf(stderr, "PEM_read_RSA_PUBKEY() failed\n");

	fclose(fp);
	return key;
}

static void init_pk_list(const char *keyfiles)
{
	struct pk_entry *entry;
	char *tmp_keyfiles;
	char *keyfile;

	tmp_keyfiles = strdup(keyfiles);

	while ((keyfile = strsep(&tmp_keyfiles, ", \t")) != NULL) {
		if (!keyfile)
			break;
		if ((*keyfile == '\0') || (*keyfile == ' ') ||
		    (*keyfile == '\t'))
			continue;

		entry = malloc(sizeof(struct pk_entry));
		if (!entry) {
			perror("malloc");
			break;
		}

		entry->key = read_pk(keyfile);
		if (!entry->key) {
			free(entry);
			continue;
		}

		get_keyid(&entry->keyid, entry->name, entry->key);
		sprintf(entry->name, "%x", __be32_to_cpup(&entry->keyid));
		entry->next = public_keys;
		public_keys = entry;
	}
}

static void hexdump(uint8_t *b, int l)
{
	int i;
	for (i=0; i < l; i++)
		printf("%02X",b[i]);
	printf(" ");
}

static int gethex(char c)
{
	if (isxdigit(c)){
		if (isdigit(c))
			return (c - '0');
		if (isupper(c))
			return (c - 'A' + 10);
		else
			return (c - 'a' + 10);
	}
	return 0;
}

static void init_pcr(char *p)
{
	int i, len = strnlen(p, MAX_DATA_HASH * 2);
	for (i=0; i < len; i += 2) {
		pcrten_target[i / 2] = gethex(p[i]) * 16 
			+ gethex(p[i + 1]);
	}
	printf("\nTarget pcrten: ");
	hexdump(pcrten_target, MAX_DATA_HASH);
	printf("\n");
}

static int read_tcg_tlv(struct tlv *tlv)
{
	memset(tlv, 0, sizeof(struct tlv));
	if (read(0, (void *)&(tlv->t), 1) == 0)
		return 0;
	if (read(0, (void *)&(tlv->l), 4) != 4)
		return 0;
	/* if too long, should abort, but let's try safely */
	if (tlv->l > (MAX_TLV - 5))
		tlv->l = MAX_TLV - 5;
	if (read(0, (void *)(tlv->v), tlv->l) != tlv->l)
		return 0;
	return 1;
}

static void print_mode(uint16_t mode)
{
	printf("\nMode ");
	/* owner */
	if (mode & S_IRUSR)
		putchar('r');
	else
		putchar('-');
	if (mode & S_IWUSR)
		putchar('w');
	else
		putchar('-');
	if (mode & S_ISUID)
		putchar('s');
	else if (mode & S_IXUSR)
		putchar('x');
	else
		putchar('-');

	/* group */
	if (mode & S_IRGRP)
		putchar('r');
	else
		putchar('-');
	if (mode & S_IWGRP)
		putchar('w');
	else
		putchar('-');
	if (mode & S_ISUID)
		putchar('s');
	else if (mode & S_IXGRP)
		putchar('x');
	else
		putchar('-');

	/* other */
	if (mode & S_IROTH)
		putchar('r');
	else
		putchar('-');
	if (mode & S_IWOTH)
		putchar('w');
	else
		putchar('-');
	if (mode & S_IXOTH)
		putchar('x');
	else
		putchar('-');
	putchar(' ');
}

static void extend(uint8_t *pcr, uint8_t *v, int l)
{
	SHA_CTX ctx;
	int i;

	/* check if violation, and invert */
	for (i=0; i < l; i++)
		if (v[i])
			break;
	if (i == l)
		memset(v, 0xff, l);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, pcrten, SHA1_HASH_LEN);
	SHA1_Update(&ctx, v, l);
	SHA1_Final(pcrten, &ctx);
}

static void check_pcrten()
{
	int i;
	for (i=0; i< MAX_DATA_HASH; i++)
		if (pcrten[i] != pcrten_target[i])
			return;
	printf(" \nPCR-10 calculated matches target! ");
}

static void hash_tlv(uint8_t *hash, struct tlv *tlv)
{
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, &(tlv->t), 1);	
	SHA1_Update(&ctx, &(tlv->l), 4);
	SHA1_Update(&ctx, tlv->v, tlv->l);
	SHA1_Final(hash, &ctx);
}

static void display_tcg_base(struct tlv *tlv)
{       
	if (tlv->t == IMA_TLV_SEQ)
		{printf("\n*****************IMA-EVENT (CEL-TLV)*************************");
		printf("\nSEQNUM %08d ", *(uint32_t *)(tlv->v));}
	else if (tlv->t == IMA_TLV_PCR)
		printf("\nPCRNUM %02d ", *(uint8_t *)(tlv->v));
	else if (tlv->t == IMA_TLV_DIGEST_SHA1) {
		printf("\nSHA1 ");
		hexdump(tlv->v, tlv->l);
		memcpy(content_digest, tlv->v, tlv->l);
		extend(pcrten, tlv->v, tlv->l);
	} else {
		printf("\ntcg_base %02d %02d ",tlv->t, tlv->l);
		hexdump(tlv->v, tlv->l);
	}
}

static void display_ima_base(struct tlv *tlv)
{
	char buf[64];
	struct tm *lt;
	int i;

	if (tlv->t == IMA_TLV_CONTENT_PATH) {
		printf("\nPATH ");
		for (i=0; i< tlv->l; i++)
			printf("%c",(tlv->v)[i]);
		printf(" ");
	} else if (tlv->t == IMA_TLV_CONTENT_DATAHASH) {
		printf("\nDATA_HASH SHA256 ");
		hexdump(tlv->v, tlv->l);
		data_hash_len = tlv->l;
		memcpy(data_hash, tlv->v, tlv->l);
	} else if (tlv->t == IMA_TLV_CONTENT_OWNER)
		printf("\nOWNER %d ",*((uint32_t *)tlv->v));
	else if (tlv->t == IMA_TLV_CONTENT_GROUP)
		printf("\nGROUP %d ",*((uint32_t *)tlv->v));
	else if (tlv->t == IMA_TLV_CONTENT_MODE)
		print_mode(*((uint16_t *)tlv->v));
	else if (tlv->t == IMA_TLV_CONTENT_TIMESTAMP) {
		lt = localtime((time_t *)(tlv->v));
		strftime(buf, 64, "%c ", lt);	
		printf("\nTimestamp %s ", buf);	
	} else if (tlv->t == IMA_TLV_CONTENT_DATASIG) {
		printf("\nDATA_SIG ");
		hexdump(tlv->v, tlv->l);
		data_sig_len = tlv->l;
		memcpy(data_sig, tlv->v, tlv->l);
	} else
		printf("\nUnregognized type %d len %d ", tlv->t, tlv->l);
}

static void display_tcg_digest(struct tlv *tlv)
{
	struct tlv temp;
	int i;

	printf("\nTCG_DIGEST ");
	/* digest is nested, copy and call base */
	temp.t = tlv->v[0];
	temp.l = tlv->l -5;
	for (i=0; i<temp.l; i++)
		temp.v[i] = tlv->v[i+5];
	display_tcg_base(&temp);
}

static void display_ima_content(struct tlv *tlv)
{
	struct tlv temp;
	int pos;

	data_sig_len = 0;
	data_hash_len = 0;

	/* walk through nested IMA tlv's, copy to temp tlv for alignment */
	for (pos=0; pos < tlv->l;) {
		temp.t = tlv->v[0 + pos];
		temp.l = *(uint32_t *)&(tlv->v[1 + pos]);
		memcpy(temp.v, (tlv->v) + pos + 5, temp.l);
		display_ima_base(&temp);
		pos += temp.l + 5;
	}

	/* check signature */
	if (data_sig_len && data_hash_len) {
		if (verify_ima_sig(data_sig, data_sig_len, 
		    data_hash, data_hash_len)) {
			printf("\nSignature invalid. ");
		} else {
			printf("\nSignature valid. ");
		}
	}
	/* now get the sha1 of the whole content TLV */
	hash_tlv(content_hash, tlv);
	if (!memcmp(content_hash, content_digest, SHA1_HASH_LEN)) {
		printf("\nDigest Matches content. ");
	} else {
		printf("\nSHA1 of content: ");
		hexdump(content_hash, SHA1_HASH_LEN);
	}
	check_pcrten();
	printf("\n");
}

static void display_tcg_tlv(struct tlv *tlv)
{
	if (tlv->t == IMA_TLV_DIGEST)
		display_tcg_digest(tlv);
	else if (tlv->t == IMA_TLV_CONTENT)
		display_ima_content(tlv);
	else
		display_tcg_base(tlv);
}

int main(int argc, char *argv[])
{
	struct tlv tlv;
	memset(pcrten,0,MAX_DATA_HASH);
	memset(pcrten_target,0,MAX_DATA_HASH);
	int pk_initialized = 0;
	
	if (argc == 3) {
		if (argv[1][1] == 'k') {
			init_pk_list(argv[2]);
			pk_initialized = 1;
		} else if (argv[1][1] == 'p')
			init_pcr(argv[2]);			
	}		
	if (argc == 5) {
		if (argv[3][1] == 'k') {
			init_pk_list(argv[4]);
			pk_initialized = 1;
		} else if (argv[3][1] == 'p')
			init_pcr(argv[4]);			
	}		
	if (!pk_initialized)
		init_pk_list("./ima_pub.pem");

	while (read_tcg_tlv(&tlv))
		display_tcg_tlv(&tlv);

	printf("\nFinal pcr-10 should be ");
	hexdump(pcrten, SHA1_HASH_LEN);
	printf("\n");
}
