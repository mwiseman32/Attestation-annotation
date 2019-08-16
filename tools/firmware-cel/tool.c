/* 
 * tool
 * 
 * SPDX-License-Identifier: BSD-3 2-Clause 
 * Copyright (C) 2019 GE
 * Author:  Avani Dave <avani.dave@ge.com>
 * 
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * tool reads eventlog blob in new eventlog2.0 structure specified by TCG from stdin, parses it, verifies it,
 * and displays the data and the verification results to stdout.
 * For each record, number of Hash Algorithms supported is matched with the enabled Algorithms from first TPM1.2 byt event. 
 * the result of this is placed in a file called result.txt which indicates number of matched and not matched event algorithms
 * the TCG digest is verified against the content, 
 * the Uitility is supplied to get hexdump of the blob for sending eventlog  
 * A sample shell script and blobs are supplied to run the Utility for testing functionality. it generates different tests result 
 * and same the stdout data into files    inside results folder along with result.txt which provides number of algorithms match not match counts 
 *
 * usage:tool [blobfile] [-a hexdump]
 *
 * Limitations: 
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* TCG Digest Size */
#define HASH_COUNT 2
#define SHA1_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define Max_algo 2
#define Max_event 4096
#define Max_venderinfo 255
#define SHA_DIGEST_LENGTH 20
#define Number_of_tests 1
#define SHA256_DIGEST_SIZE1 49

/* TCG Specific content type*/ 
int counter =1;int match=0;int missed=0;
typedef u_int16_t TPM_ALG_ID;
typedef TPM_ALG_ID TPMI_ALG_HASH ;
typedef union TPMU_HA TPMU_HA;	

/* Color defination for message display */
void red () {
        printf("\033[1;31m");
    }

void yellow () {
        printf("\033[1;33m");
    }

void green () {
        printf("\033[1;32m");
    }
 
void white () {
        printf("\033[1;37m");
    }
 
void blue () {
       printf("\033[1;34m");
    }

void reset () {
      printf("\033[0m");
    }
#pragma pack(1)

/* Structures defination for eventlog */
typedef struct {
        TPMI_ALG_HASH  hashAlg;
	u_int8_t digest[SHA256_DIGEST_SIZE1];
    }TPMT_HA;

typedef struct {
	u_int32_t   count;
        TPMT_HA  digests[HASH_COUNT] ;
    }TPML_DIGEST_VALUES;

typedef struct {
	u_int16_t alg_id ;
	u_int16_t digest_size ;
    }tcg_efi_specid_event_algs; 

typedef struct {
	u_int8_t signature[16];
        u_int32_t platform_class;
	u_int8_t spec_version_minor;
	u_int8_t spec_version_major;
	u_int8_t spec_errata;
	u_int8_t u_intnsize;
	u_int32_t num_algs;
	tcg_efi_specid_event_algs digest_sizes[Max_algo];
	u_int8_t vendorinfo;
	//u_int8_t vendorinfo1[Max_venderinfo];		
    }efispecideventhead;

typedef struct {
	u_int32_t pcr;
	u_int32_t type;
 	TPML_DIGEST_VALUES digests;
 	u_int32_t event_z;
    }pcr_event2;

typedef struct {
	u_int32_t pcr_idx;
  	u_int32_t event_type;
  	u_int8_t digest[SHA_DIGEST_LENGTH];
  	u_int32_t event_size;
    }pcr_event1;

typedef struct event event;
struct __attribute__((packed))event {
	pcr_event1 header1; 
	efispecideventhead efispecideventhead;
    };	

typedef struct event2 event2; 
struct  __attribute__((packed))event2 {
	pcr_event2 header2; 
	u_int8_t event[Max_event];
    };
#pragma pack(1)

/* Function for raw hexdump to output_file */
static void hexdump1(u_int32_t *data, int size, FILE* out_file) {
        int i;
	for (i=0; i < size; i++)
	fprintf(out_file,"%02X ",data[i]);
    }

/* Function for hexdump eventlog2 */
static void hexdump(u_int8_t *b, int l) {
	int i;
	for (i=0; i < l; i++) {
	    printf("%02X ",b[i]);
	}
    }

/* Function for hexdump for Edge case */
static void hexdump2(u_int8_t *b, int l) {
	int i;
	for (i=0; i < l; i++) {
	    printf("%02X ",b[i+1]);
        }
    }

/* Function for pretty hexdump to output_file*/
static void dumphex(const void* data, size_t size, FILE* out_file) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    int addr=0;
    fprintf(out_file,"%08X  ", addr);
    for (i = 0; i < size; ++i) {        
        fprintf(out_file,"%02X ", ((unsigned char*)data)[i]);
	if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
	    ascii[i % 16] = ((unsigned char*)data)[i];
	} 
        else {
            ascii[i % 16] = '.';
	}
	if ((i+1) % 8 == 0 || i+1 == size) {
            fprintf(out_file," ");
	    if ((i+1) % 16 == 0) {
                fprintf(out_file,"|%s|\n", ascii);
		addr=addr+16; 
		fprintf(out_file,"%08X  ", addr);
	    } 
	    else if (i+1 == size) {
		ascii[(i+1) % 16] = '\0';
            if ((i+1) % 16 <= 8) {
	        fprintf(out_file," ");
            }
	    for (j = (i+1) % 16; j < 16; ++j) {
		fprintf(out_file,"   ");
	    }
	    fprintf(out_file,"|  %s \n", ascii);
	    }
        }
    }
}

/* Function to display first event in tpm1.2 format */
static void display_event12(struct event *event) {
    int i=0;
    printf("\n");
    printf("\n*****************TPM-1.2-EVENT (CEL-TLV)*************************");
    printf("\nEvent seqNumber           : %08d", counter-1);
    printf("\nEvent PCRIndex            : %08x ", event->header1.pcr_idx);
    printf("\nEvent eventType           : %08x ", event->header1.event_type);
    printf("\nEvent Digests             : ");hexdump(event->header1.digest, SHA_DIGEST_LENGTH);
    printf("\nEvent Len                 : %08x ", event->header1.event_size);
    printf("\nEvent Signature           : ");
    
    for(int j=0;j<16;j++) {
        printf("%02x",(event->efispecideventhead.signature[j]));
    }
	  
    printf("\nEvent platform_class      : %08x", event->efispecideventhead.platform_class);
    printf("\nEvent Spec Version Minor  : %02x", event->efispecideventhead.spec_version_minor);
    printf("\nEvent Spec Version Major  : %02x", event->efispecideventhead.spec_version_major);
    printf("\nEvent spec_errata         : %02x", event->efispecideventhead.spec_errata);
    printf("\nEvent u_intnsize          : %02x", event->efispecideventhead.u_intnsize);
    printf("\nEvent num_algs            : %08x", event->efispecideventhead.num_algs);
        yellow();
        printf(" CHECKING ");
        reset();
        white();
        printf("**: ");
        reset();
        green();
        printf("Number of algorithms supported is");
        reset();
        white();
        printf(" :%02x",event->efispecideventhead.num_algs);
        reset();
    if(event->efispecideventhead.num_algs==1) {
	printf("\nEvent alg_id              : %04x", event->efispecideventhead.digest_sizes[0].alg_id);
	printf("\nEvent digest_size         : %04x", event->efispecideventhead.digest_sizes[0].digest_size);
    }
    else {
        for(int j=0;j<event->efispecideventhead.num_algs;j++) {
	    printf("\nEvent alg_id              : %04x", event->efispecideventhead.digest_sizes[j].alg_id);
	    printf("\nEvent digest_size         : %04x", event->efispecideventhead.digest_sizes[j].digest_size);
	}
    }
	printf("\nEvent Vendor Info         : %02x", event->efispecideventhead.vendorinfo);
	FILE *out_file= fopen("hexdump.txt", "w");
        dumphex(&event->header1.pcr_idx,300,out_file);
        fclose(out_file);		
}

/* Function to read first event in tpm1.2 format*/
static int read_event12(struct event *event, FILE *fp) {	  
    enum {SIZE = 1};
    fread((void *)& (event->header1.pcr_idx),4, 1, fp);
    fread((void *)& (event->header1.event_type),4, 1, fp);
    fread((void *)& (event->header1.digest),SHA_DIGEST_LENGTH, 1, fp);
    fread((void *)& (event->header1.event_size),4, 1, fp);
    fread((void *)& (event->efispecideventhead.signature[0]),16, 1, fp);
    fread((void *)& (event->efispecideventhead.platform_class),4, 1, fp);
    fread((void *)& (event->efispecideventhead.spec_version_minor),1, 1, fp);
    fread((void *)& (event->efispecideventhead.spec_version_major),1, 1, fp);
    fread((void *)& (event->efispecideventhead.spec_errata),1, 1, fp);
    fread((void *)& (event->efispecideventhead.u_intnsize),1, 1, fp);
    size_t num_Alg=fread((void *)& (event->efispecideventhead.num_algs),4, 1, fp);
    if(num_Alg ==SIZE) {
        if(event->efispecideventhead.num_algs==1) {
	    fread((void *)& (event->efispecideventhead.digest_sizes[0].alg_id),2, 1, fp);
	    fread((void *)& (event->efispecideventhead.digest_sizes[0].digest_size),2, 1, fp);
	}
	else {
            for(int p=0; p< event->efispecideventhead.num_algs; p++) {
	        fread((void *)& (event->efispecideventhead.digest_sizes[p].alg_id),2, 1, fp);
	        fread((void *)& (event->efispecideventhead.digest_sizes[p].digest_size),2, 1, fp); 
	    }
	}		  	
    }
    fread((void *)& (event->efispecideventhead.vendorinfo),1, 1, fp);
}

/* Function to determine size of hash digest and read it in event2 data structure */
static int read_hash(struct event2 *event2,int hashcheck, int k,FILE *fp) {
    
    switch(hashcheck) 
    {
    case 4 :	  
        fread((void *)& (event2->header2.digests.digests[k].digest[k]),SHA1_DIGEST_SIZE, 1, fp);	
        break;
    case 11 :
        fread((void *)& (event2->header2.digests.digests[k].digest[k]),SHA256_DIGEST_SIZE, 1, fp);
        break;
    case 16 :  
	fread((void *)& (event2->header2.digests.digests[k].digest[k]),SHA384_DIGEST_SIZE, 1, fp);	
	break;
    default : 
	yellow();
	printf("WARNING ");
	reset();
	white();
	printf("**: ");
	reset();
	blue();
	printf("Not supported algorithm found");
	reset();	
    }
}
/* Function to read event2 data structure */
static int  read_event20(struct event2 *event2, FILE *fp) {	  
    enum {SIZE = 1};
    int k=0;
    enum {SHA1 =0004,SHA256 = 0011, SHA384 = 0012};
    fread((void *)& (event2->header2.pcr),4, 1, fp);
    fread((void *)& (event2->header2.type),4, 1, fp);
    size_t ret_count=fread((void *)& (event2->header2.digests.count),4, 1, fp);
    if(ret_count == SIZE) { 
        if(event2->header2.digests.count==1) {
	size_t ret_algsingle=fread((void *)& (event2->header2.digests.digests[0].hashAlg),2, 1, fp);
	    if(ret_algsingle==SIZE) {
            int hashcheck= event2->header2.digests.digests[0].hashAlg;
            read_hash(event2,hashcheck,k,fp);
	    }
            } else { 
	    for(int k=0;k<event2->header2.digests.count;k++) {	
	    size_t ret_alg=fread((void *)& (event2->header2.digests.digests[k].hashAlg),2, 1, fp);
        if(ret_alg==SIZE) { 
        int hashcheck= event2->header2.digests.digests[k].hashAlg;
	read_hash(event2,hashcheck,k,fp);
        }
        }
    }
    }
    fread((void *)& (event2->header2.event_z),4, 1, fp);
    fread((void *)(event2->event), event2->header2.event_z,1,fp);
   // return 1; 	
}

/* Function to display event2 digests */
static void display_digest(struct event2 *event2,int hashAlg1, int k) {
    
    switch(hashAlg1)
    {
    case 4 :
       	hexdump(event2->header2.digests.digests[k].digest,SHA1_DIGEST_SIZE);
        break;
    case 11 :	
        if (k==0) {
	    hexdump(event2->header2.digests.digests[k].digest,SHA256_DIGEST_SIZE);
	} else {
            hexdump2(event2->header2.digests.digests[k].digest,SHA256_DIGEST_SIZE);						       
	}
        break;
    case 12 :
        hexdump2(event2->header2.digests.digests[k].digest,SHA384_DIGEST_SIZE);
        break;
    default :  
        yellow();
        printf("WARNING ");
        reset();
        white();
        printf("**: ");
        reset();
        blue();
        printf("Not supported algorithm found");
        reset();
    }		
}

/* Function to display all tpm2.0 events */
static int display_event20(struct event2 *event2, struct event *event) {	 
    int k=0;
    typedef enum { SHA1 = 0004,SHA256 = 0011, SHA384 = 0012 } Algorithm;
    Algorithm check;	
    printf("\n*****************TPM2.0-EVENT (CEL-TLV)*************************");
    printf("\nEvent seqNumber           : %08d", counter++);
    printf("\nEvent PCRIndex            : %08x ", event2->header2.pcr);
    printf("\nEvent eventType           : %08x ", event2->header2.type);
    printf("\nEvent Count               : %08x ", event2->header2.digests.count);
    if(event->efispecideventhead.num_algs!=event2->header2.digests.count) {   
	yellow();
        printf("WARNING ");
        reset();
        white();
        printf("**: ");
        reset();
	blue();
        printf("Number of algorithms supported doesn't match ");
        reset();
	missed=missed+1;
    } else {  
	yellow();
        printf("CHECKING ");
        reset();
        white();
        printf("**: ");
        reset();
        green();
        printf("Number of algorithms supported matches ");
        reset();
        match++;
    }
    if(event2->header2.digests.count==1) {   
        printf("\nEvent Digests[%x].AlgID    : %04x ",k, event2->header2.digests.digests[k].hashAlg);  
	int hashAlg1=event2->header2.digests.digests[0].hashAlg;
	printf("\nEvent Digests[%x].Digest   : ",k);
	display_digest(event2, hashAlg1,k);
    } else {
        for(int k=0;k<event2->header2.digests.count;k++) {  
	printf("\nEvent Digests[%x].AlgID    : %04x ",k, event2->header2.digests.digests[k].hashAlg); 
        int hashAlg2=event2->header2.digests.digests[k].hashAlg;
	printf("\nEvent Digests[%x].Digest   : ",k);
	display_digest(event2, hashAlg2, k);
	}
    }
    printf("\nEvent dataSize            : %08x ", event2->header2.event_z);
    printf("\nEvent Data                : ");
    hexdump(event2->event,event2->header2.event_z);  
}
/* Function to determine size of hash digest and read it in event2 data structure */
static void statcheck1(int hashVal) {	  
    FILE *out_file= fopen("result.txt", "a");
    const char *Alg[]={"SHA1","SHA256", "SHA384"};
	  
    switch(hashVal)
    {
    case 4  :
        fprintf(out_file," %s |",Alg[0]);
        break;
    case 11 :
        fprintf(out_file," %s |",Alg[1]);
        break;
    case 12 :
	fprintf(out_file," %s |",Alg[2]);
        break;
    default :
	fprintf(out_file," %d |",hashVal);
    }
}


int main(int argc, char *argv[]) {         
    FILE *fp;
    int i,j=0;
    struct stat buf;
    struct event event;
    struct event2 event2;
    fp = fopen(argv[1], "r");
    fseek(fp, 0L, SEEK_END);
    int sz = ftell(fp);
    rewind(fp);	   
    if(fp==NULL) {
	perror("unable to open pcr file\n");
        return 1;
    }  

    if (argv[3][0] == 'a') {
	FILE *out_file= fopen("hexdump.txt", "w");
	printf("\n%d\n",sz);
        dumphex(fp,sz,out_file);
	fclose(out_file);
    } else if (argv[3][0] == 's') {
        //FILE *out_file= fopen("hexdump1.txt", "a"); here I am planning to update one more option for now its a placeholder
        //fprintf(out_file,"\nHi Avani ");
        //dumphex(fp,sz,out_file);
        //fprintf("\n**********TPM2.0-EVENT LOG STATS******************************");
	//printf("\nNumber of hashAlg matched  : %08d", match);
        //printf("\nNumber of hashAlg not match: %08d", missed);  
	// fclose(out_file);
    } else { 
	read_event12(&event , fp);
	display_event12(&event);	
	memset(&event2,0,sizeof(&event2));
	while((ftell(fp)!=sz)) {
	    read_event20(&event2,fp);
	    display_event20(&event2,&event);
        }
	
        FILE *out_file= fopen("result.txt", "a");
        fprintf(out_file,"\n**********TPM2.0-EVENT LOG STATS******************************");
        if(event.efispecideventhead.num_algs==1) {
            int hashVal=event.efispecideventhead.digest_sizes[0].alg_id;
	    statcheck1(hashVal);
        } else {
            for(int j=0;j<event.efispecideventhead.num_algs;j++) {
            int hashVal=event.efispecideventhead.digest_sizes[j].alg_id;
	    statcheck1(hashVal);
            }
        fprintf(out_file,"\nNumber of hashAlg matched  : %02d", match);
        fprintf(out_file,"\nNumber of hashAlg not match: %02d", missed);  
        fclose(out_file);
        }   
    }
    fclose(fp);
}
