obj-m += net_intercept.o
net_intercept-objs := net_interception.o packet_parser.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
