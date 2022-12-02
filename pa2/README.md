Q size = 20
average: 0.656133333333
standard deviation: 0.269651182085

Q size = 100
average: 1.37578787879
standard deviation: 0.868114562946


1. Why do you see a difference in webpage fetch times with small and large router buffers?
We know that the input link's bandwidth is much larger than the downstream link. Based on TCP's behaviour, the congestion window will continue to 
grow and eventually outgrow the exit rate of packets.
Because packets are processed in FIFO, the time it takes for a packet to be dropped grows in proportion to the queue size as packets will spend more time waiting to be processed or dropped.

In essence
- Longer buffer => Longer queue => longer wait 
- shorter buffer => shorter queue => shorter wait.

Therefore, we see a disparity between large and small route buffers when a new TCP connection is established and packets are added to the end of the queue.

2. Buffer bloat can occur in other places such as your network interface card (NIC). Check the output of ifconfig eth0 on your VirtualBox VM. What is the (maximum) transmit queue length on the network interface reported by ifconfig? 
For this queue size and a draining rate of 100 Mbps, what is the maximum time a packet might wait in the queue before it leaves the NIC?

- Maximum queue length is 1000 packets
- MTU of a packet is 1500 bytes
- Drain Rate 100Mbps
- This means that the queue can store up to 1000 * 1500 * 8 = 1.2Mbps. Draining the queue takes 1.2 / 100 = 0.12s

3. How does the RTT reported by ping vary with the queue size? Write a symbolic equation to describe the relation between the two (ignore computation overheads in ping that might affect the final result).

- Let Q be queue size
Assuming all packets are all 64 bytes, RTT ~= 2.5 * Q . RTT varies between 2 * Q and 2.5 * Q

4. Identify and describe two ways to mitigate the bufferbloat problem.
- Keep the buffer size to a small reasonable amount

- Another way is to use an active queue management algorithm such as random early detection so that the packets are dropped before the queue becomes full, which curbs the size of the congestion window and the average time packets spend inside the buffer