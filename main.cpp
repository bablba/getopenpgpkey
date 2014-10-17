/*
gcc main.cpp -lunbound -lcrypto -o getopenpgpkey

*/

#include <stdio.h>	/* for printf */
#include <arpa/inet.h>  /* for inet_ntoa */
#include <unbound.h>	/* unbound API */
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <errno.h>

#define EXIT_FAILURE 1
#define SUCCESS 0

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define MAX_EMAIL_LENGTH 254
#define MAX_DOMAIN_LENGTH 253

bool simpleSHA224(void* input, unsigned long length, unsigned char* md)
{
    SHA256_CTX context;
    if(!SHA224_Init(&context))
        return false;

    if(!SHA224_Update(&context, (unsigned char*)input, length))
        return false;

    if(!SHA224_Final(md, &context))
        return false;

    return true;
}



void create_entry(FILE *fpin)
{
  /// outputs the data part of DNS entry for data
  FILE *fpout = tmpfile();

  char buffer[3];

  
  int lc = 0;
  int byte_count = 0;
  
  fprintf(fpout,"\t");
  while (fread(buffer, 1, 1, fpin) == 1) {
    fprintf(fpout,"%.2x",(unsigned char)*buffer);
    byte_count++;
    lc+=1;
    if(lc==32){lc = 0; fprintf(fpout,"\n\t");}
  }

  fprintf(stdout,"%d\n",byte_count);
  fseek(fpout,0,SEEK_SET);

  // output tmp file to stdout
  char buffer2[1024];
  size_t bytes;

  while (0 < (bytes = fread(buffer2, 1, sizeof(buffer2), fpout)))
    fwrite(buffer2, 1, bytes, stdout);  

  

  fclose(fpout);

}

bool email_to_key(char *email,char *keyout)
{
  unsigned char md[SHA224_DIGEST_LENGTH]; // 224 bits :D

  if(strlen(email)>MAX_EMAIL_LENGTH) return false;

  // what's the max length of an email address?? 254? 
  char copy[MAX_EMAIL_LENGTH+1];
  copy[MAX_EMAIL_LENGTH] = 0;
  memset(&copy,0,MAX_EMAIL_LENGTH+1);
  strncpy(copy, email,MAX_EMAIL_LENGTH);

  int count = 0;
  unsigned char *p = (unsigned char *)copy;
  do{
    if(*p==0) { return false;} // no @
    if(*p=='@') {*p=0; break;}
    p++;
    count++;
  }while(1);
  if(count>MAX_EMAIL_LENGTH) return false;
  char *domain = (char *)(p+1);
  char *user = (char *)copy;

  //printf("Domain: %s\n",domain);
 // printf("User: %s\n",user);

  if (!simpleSHA224(user,strlen(user),md)) return false;

  
  char hex[(SHA224_DIGEST_LENGTH*2)+1]; // 224 bits + 1
  hex[SHA224_DIGEST_LENGTH*2] = 0;
  int i;
 
  for (i = 0; i < SHA224_DIGEST_LENGTH; i++)
  {
      sprintf(hex+(i*2),"%02x", md[i]);
  }

  sprintf(keyout,"%s._openpgpkey.%s",hex,domain);



  return true;
}

void usage(char **argv)
{
 fprintf(stderr, "Create and look up OPENPGPKEY entries.\n");
 fprintf(stderr, "This program does not touch your keyring.\n\n");

 fprintf(stderr, "  Usage: %s [options] email\n",
                           argv[0]);
 fprintf(stderr,
  "\n"
  "  Options:\n"
  "\n"
  "   -k         Calculate key of email address (default)\n"
  "   -l         Fetch and output DNS entry data for email address\n"
  "   -b         Allow binary output if data is not printable (use for piping)\n"
  "   -a         Throw output to gpg and see what it says (instead of -b | gpg)\n"
  "\n"
  "   -c         Create type 61 DNS entry based on email address and input\n"
  "   -f [file]      use file instead of stdin\n"

  "\n\n");

  fprintf(stderr,"   Examples:\n");
  fprintf(stderr,"   %s noone@example.com\n",argv[0]);
  fprintf(stderr,"   %s -c noone@example.com -f mypublickey.txt\n",argv[0]);
  fprintf(stderr,"   %s -l noone@example.com\n",argv[0]);
;
  fprintf(stderr,"\n");
}
int main(int argc, char **argv)
{
	struct ub_ctx* ctx;
	struct ub_result* result;
	int retval;


 int binary = 0;
 int armor = 0;
 int lookup = 0;
int outputkey = 0;
int create = 0;
  int opt;
char *filename;
int usefile = 0;

           while ((opt = getopt(argc, argv, "ckbalf:")) != -1) {
               switch (opt) {
              case 'f':
                create = 1;
                usefile = 1;
                filename = optarg;
                break;
              
               case 'c':
                   create = 1;
                   break;
               case 'b':
                   binary = 1;
                   break;
               case 'k':
                   outputkey = 1;
                   break;
                case 'a':
                   armor = 1;
                   break;
                case 'l':
                   lookup = 1;
                   break;
                default: /* '?' */
                   usage(argv);
                   return 1;
            case '?':
            if (optopt == 'f')
              fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
              fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
              fprintf (stderr,
                       "Unknown option character `\\x%x'.\n",
                       optopt);
              return 1;
               }
           }
  if (optind >= argc) {
    usage(argv);
    return 0;
  }

  if(!(lookup | armor | outputkey) ) {
    outputkey = 1;
  }
  if(binary | armor) {
    lookup = 1;
  }
 if(binary | armor) {
    outputkey = 0;   
  }
 if(create) {
    outputkey = 0; lookup = 0;   
  }
  char *email = argv[optind];

  


	/* create context */
	ctx = ub_ctx_create();
	if(!ctx) {
		fprintf(stderr,"error: could not create unbound context\n");
		return 1;
	}
  
  char keyout[(SHA224_DIGEST_LENGTH*2)+strlen("._openpgpkey.")+MAX_EMAIL_LENGTH+1]; //(224 bits in bytes plus 1) + max domain name length

  //printf("Calculating key for: %s\n", email);
  if(!email_to_key(email, keyout)) {
    fprintf(stderr,"This doesn't look like an email address to me\n");
    return 1;
  }
  if(outputkey) printf("%s\n" ,keyout);
//  else fprintf(stderr, "%s\n" ,keyout); // Show it anyway to stderr?

  if(create)
  {
    FILE *readfile = stdin;

    if(usefile)
      {
       FILE *fd = fopen(filename,"r");
       if(errno || (NULL == fd))
        {
            // Use strerror to display the error string
            printf("\n[%s]\n",(char*)strerror(errno));
            return EXIT_FAILURE;
        }
        readfile = fd;
    
      }


    fprintf(stdout,"%s. IN TYPE61 \\# (", keyout);
    create_entry(readfile);
    fprintf(stdout,")\n\n");
    return SUCCESS;


  }



  if(!lookup) return 0;

	/* query for webserver */
	retval = ub_resolve(ctx, keyout, 
		61 /* TYPE A (IPv4 address) */, 
		1 /* CLASS IN (internet) */, &result);
	if(retval != 0) {
		fprintf(stderr,"resolve error: %s\n", ub_strerror(retval));
		return 1;
	}

 
	/* show first result */
	if(result->havedata)
		{ 

       if(!armor){
          int count = *(result->len);
          char *p = *(result->data);
          while(count--)
          {
            char c = *p++;
            if(!binary){if (!isprint(c) && c!='\n'&& c!='\t' && c!='\r') {printf("Not ascii data. Aborting. Try with the -b flag.\n"); return 1;}}
            fputc(c,stdout);
/*            char t[2];t[1] = 0; t[0] = c;
            printf("%s",t);
*/
          }
          fflush(stdout);
      }
      else
      {


    FILE *output;

    output = popen ("gpg --dry-run ", "w");
    if (!output)
      {
        fprintf (stderr,
                 "incorrect parameters or too many files.\n");
        return EXIT_FAILURE;
      }



        int count = *(result->len);
         char *p = *(result->data);
          while(count--)
          {
            char c = *p++;
            fputc(c,output);

          }
   




    if (pclose (output) != 0)
      {
        fprintf (stderr,
                 "Could not run more or other error.\n");
      }












      }
      



    }else
  {
    fprintf(stderr,"The DNS record does not appear to exist. (Or DNSSEC is broken on it.)\n");
    fprintf(stderr,"Please make one because OPENPGPKEY is cool.\n");
    
  }
 

	ub_resolve_free(result);
	ub_ctx_delete(ctx);
	return 0;
}
