Q size = 20
average: 0.2005
standard deviation: 0.157618943917

Q size = 100
average: 0.269666666667
standard deviation: 0.639612188466
=======
Q Size = 20
average: 0.191166666667
standard deviation: 0.121682152744

Q Size = 100
average: 0.306039215686
standard deviation: 0.688378713619


1. Why do you see a difference in webpage fetch times with small and large router buffers?
When the buffer is very large, packets spend a much longer time on average waiting in the browser before being processed or dropped. 
as a result, the round trip time of a packet in a network with a larger router buffer is much larger than a packet in a network with a smaller router buffer

2. Buffer bloat can occur in other places such as your network interface card (NIC). Check the output of ifconfig eth0 on your VirtualBox VM. What is the (maximum) transmit queue length on the network interface reported by ifconfig? For this queue size and a draining rate of 100 Mbps, what is the maximum time a packet might wait in the queue before it leaves the NIC?


3. How does the RTT reported by ping vary with the queue size? Write a symbolic equation to describe the relation between the two (ignore computation overheads in ping that might affect the final result).
- 

4. Identify and describe two ways to mitigate the bufferbloat problem.
- Making the buffer on the slower link greater than or equal to the buffer (out queue) on the faster link
- 