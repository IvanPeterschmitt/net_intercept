obj-m += net_intercept.o
net_intercept-objs := src/net_interception.o src/packet_parser.o src/param_parser.o src/packet_filter.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
