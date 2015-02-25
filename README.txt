To run the 'demo' for bandwidth control and monitoring, do the following:

1) run the server: 
	$ ryu-manager bandwidth_control_simple_switch_13.py
   this starts up a listener on the ususal port (6633) for communication with the OF 1.3 switch(es)
   it also starts a listener on 4000 for JSN-RPC requests from, e.g., the following sample client programs:

2) enforce_throughput.py and enforce_throughput_service.py
   These create port level and flow level meters respectively, to enforce through put limits at port anf low level, e.g.

       # this will add port restrictions for the switch ID '708311360087360' (on ports numbered 1 and 3)
       $ python enforce_throughput.py 708311360087360 3 1000 ; python enforce_throughput.py 708311360087360 1 1000

       # this will add flow restrictions for the switch ID '708311360087360' (on any traffic on the switch beteen the IP addresses 192.168.0.3 and 192.168.0.4)
       $ python enforce_throughput_service.py 708311360087360 192.168.0.4 192.168.0.3 5000 ; python enforce_throughput_service.py 708311360087360 192.168.0.3 192.168.0.4 5000

   Note: the switch ID is most easily found from the report outputs described next....

3) report_throughput.py
   The program has a --help/-h option - try it!
   Or try some of these invocations:
       $ python report_throughput.py -h
       $ python report_throughput.py -a
       $ python report_throughput.py -a -m
       $ python report_throughput.py -s 708311360087360
       $ python report_throughput.py -s 708311360087360 -m
       $ python report_throughput.py -s 708311360087360 -f
       $ python report_throughput.py -s 708311360087360 -f -m
       $ python report_throughput.py -s 708311360087360 -f -m -p 54
       $ python report_throughput.py -s 708311360087360 -m -p 3
       $ python report_throughput.py -s 708311360087360  -p 3

