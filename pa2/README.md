Queue size 20
Average: 0.0250666666667
Standard deviation: 0.136025716523

Queue size 100
Standard deviation: 0.211184177122
Average 0.0581

1. Why do you see a difference in webpage fetch times with small and large router buffers?
This is because the small 

2. Bufferbloat can occur in other places such as your network interface card (NIC). Check the output of ifconfig eth0 on your VirtualBox VM. What is the (maximum) transmit queue length on the network interface reported by ifconfig? For this queue size and a draining rate of 100 Mbps, what is the maximum time a packet might wait in the queue before it leaves the NIC?

3. How does the RTT reported by ping vary with the queue size? Write a symbolic equation to describe the relation between the two (ignore computation overheads in ping that might affect the final result).
- 

4. Identify and describe two ways to mitigate the bufferbloat problem.
- Making the buffer on the slower link greater than or equal to the buffer (out queue) on the faster link
- 