#include <stdio.h>


void dumphex(const void* data, size_t size, FILE* out_file) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	int addr = 0;
	fprintf(out_file,"%08X  ", addr);
	for (i = 0; i < size; ++i) {
		
		fprintf(out_file,"%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			fprintf(out_file," ");
			if ((i+1) % 16 == 0) {
				fprintf(out_file,"|%s|\n", ascii);
				addr=addr+16; 
				fprintf(out_file,"%08X  ", addr);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					fprintf(out_file," ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					fprintf(out_file,"   ");
				}
				fprintf(out_file,"| %s \n", ascii);
			}
		}
	}
}

int main(int argc, char *argv[]) 
{
	  FILE *fp;
	  int i,j=0;
	  fp = fopen(argv[1], "r");
	  fseek(fp, 0L, SEEK_END);
          int sz = ftell(fp);
	  FILE *out_file= fopen("hexdump.txt", "w");
          dumphex(fp,sz,out_file);
          fclose(out_file);
	  fclose(fp);

}
