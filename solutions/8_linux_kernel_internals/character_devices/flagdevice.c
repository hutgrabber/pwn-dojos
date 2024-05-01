#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
int main() {
  int fd;
  char buffer[512];
  char *dev = "flag_dev";
  ssize_t numBytes = 0;
  /* This should read open the device, and read in the flag to the buffer*/
  fd = open(dev, O_RDWR);
  if (fd < 0) {
    perror("Opening the device failed...");
    return errno;
  }

  /* We should get back the flag */

  numBytes = read(fd, buffer, 512);

  printf("First read = %s\n", buffer);

  /*
      We are going to replace the contents of {} within the flag.
      Note this may not be perfect. This is best effort.
  */

  lseek(fd, 12, SEEK_SET);
  numBytes = write(fd, "ENPM809V_IS_THE_BEST}", 21);

  lseek(fd, 0, SEEK_SET);
  memset(buffer, 0, 512); // Clearing the buffer
  numBytes = read(fd, buffer, 512);

  /* Should print out at a minimum pwn.college{ENPM809V_IS_THE_BEST} */
  printf("Secomd read = %s\n", buffer);

  /* Releasing the device by closing it */
  close(fd);

  return 0;
}
