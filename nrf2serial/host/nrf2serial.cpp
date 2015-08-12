#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

int main(int argc, char **argv)
{
	struct termios tio;
	int tty_fd;
	char c;

	if (argc < 2){
		printf("USAGE %s serial_port(/dev/ttyACM0 for example)\n",
								argv[0]);
		return -EINVAL;
	}

	memset(&tio,0,sizeof(tio));

	tio.c_iflag = 0;
	tio.c_oflag = 0;
	tio.c_cflag = CS8|CREAD|CLOCAL;
	tio.c_lflag = 0;
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 5;

	tty_fd = open(argv[1], O_RDWR | O_NONBLOCK);

	cfsetospeed(&tio, B9600);
	cfsetispeed(&tio, B9600);

	tcsetattr(tty_fd, TCSANOW,&tio);

	while (1){
		int read_c = read(tty_fd, &c ,1);
		if (read_c > 0)
			printf("%x\n", c & 0xFF);
	}

	close(tty_fd);

	return EXIT_SUCCESS;
}
