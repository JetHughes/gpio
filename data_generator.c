#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>


#define BCM2835_PERI_BASE        0x3f000000
#define GPIO_BASE                (BCM2835_PERI_BASE + 0x200000)

#define SIZE 1024 * 16
#define PAGE_SIZE (4*1024)
#define BLOCK_SIZE (4*1024)

int  mem_fd;
void *gpio_map;

// I/O access
volatile unsigned *gpio;

void write_to_gpio(char c)
{
volatile unsigned *gpio_set, *gpio_clear;

gpio_set = (unsigned *)((char *)gpio + 0x1c);
gpio_clear = (unsigned *)((char *)gpio + 0x28);


if(c & 1) *gpio_set = 1 << 8;
else *gpio_clear = 1 << 8;
usleep(1);

if(c & 2) *gpio_set = 1 << 18;
else *gpio_clear = 1 << 18;
usleep(1);

if(c & 4) *gpio_set = 1 << 23;
else *gpio_clear = 1 << 23;
usleep(1);

if(c & 8) *gpio_set = 1 << 25;
else *gpio_clear = 1 << 25;
usleep(1);

*gpio_set = 1 << 4;
usleep(1);
*gpio_clear = 1 << 4;
usleep(1);

}

/**
 * Thus function writes to the port 0 of the parallel port and each
 * character written to the port 0 will trigger an interrupt
 */
static int write_to_port(unsigned char *buffer, size_t count) {
  size_t written = 0;

  while (written < count) {
	write_to_gpio(buffer[written]>>4);
	write_to_gpio(buffer[written] );
    written++;
  }

  return written;
}


//
// Set up a memory regions to access GPIO
//
void setup_io()
{
   /* open /dev/mem */
   if ((mem_fd = open("/dev/mem", O_RDWR|O_SYNC) ) < 0) {
      printf("can't open /dev/mem \n");
      exit(-1);
   }

   /* mmap GPIO */
   gpio_map = mmap(
      NULL,             //Any adddress in our space will do
      BLOCK_SIZE,       //Map length
      PROT_READ|PROT_WRITE,// Enable reading & writting to mapped memory
      MAP_SHARED,       //Shared with other processes
      mem_fd,           //File to map
      GPIO_BASE         //Offset to GPIO peripheral
   );

   close(mem_fd); //No need to keep mem_fd open after mmap

   if (gpio_map == MAP_FAILED) {
      printf("mmap errorÂ %d\n", (int)gpio_map);//errno also set!
      exit(-1);
   }

   // Always use volatile pointer!
   gpio = (volatile unsigned *)gpio_map;


} // setup_io

/*The following main() function reads from a text file and writes to the virtual port (the output pins) half-byte by half-byte. The
final byte of zero indicates the end of a file.*/
int main(int argc, char **argv) {
  FILE *in;
  size_t size_read;
  int i;
  unsigned char buf[SIZE];

  if(argc < 2) {
        printf("Usage: data_generator <file1> <file2> ... \n");
        exit(0);
  }

  setup_io();

  for (i = 1; i < argc; i++) {
    if (NULL == (in = fopen(argv[i], "r"))) {
      perror(argv[i]);
      continue;
    }
    
    while (!(feof(in) || ferror(in))) {
      size_read = fread(buf, 1, SIZE, in);
      write_to_port(buf, size_read);
    }
    fclose(in);
    /* insert '\0' to signal end of file */
    write_to_gpio(0);
    write_to_gpio(0);
  }

  return EXIT_SUCCESS;
}
