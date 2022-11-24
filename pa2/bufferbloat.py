#!/usr/bin/python
"CSC458 Fall 2022 Programming Assignment 2: Bufferbloat"

from mininet.topo import Topo
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.log import lg, info
from mininet.util import dumpNodeConnections
from mininet.cli import CLI
from mininet.clean import cleanup

from subprocess import Popen, PIPE
from time import sleep, time
from multiprocessing import Process
from argparse import ArgumentParser

from monitor import monitor_qlen
import termcolor as T

import sys
import os
import math
import helper

# TODO: Don't just read the TODO sections in this code.  Remember that
# one of the goals of this assignment is for you to learn how to use
# Mininet.

parser = ArgumentParser(description="Bufferbloat tests")
parser.add_argument('--bw-host', '-B',
                    type=float,
                    help="Bandwidth of host links (Mb/s)",
                    default=1000)

parser.add_argument('--bw-net', '-b',
                    type=float,
                    help="Bandwidth of bottleneck (network) link (Mb/s)",
                    required=True)

parser.add_argument('--delay',
                    type=float,
                    help="Link propagation delay (ms)",
                    required=True)

parser.add_argument('--dir', '-d',
                    help="Directory to store outputs",
                    required=True)
                    # Maybe change defualt to ./

parser.add_argument('--time', '-t',
                    help="Duration (sec) to run the experiment",
                    type=int,
                    default=10)

parser.add_argument('--maxq',
                    type=int,
                    help="Max buffer size of network interface in packets",
                    default=100)

# Linux uses CUBIC-TCP by default that doesn't have the usual sawtooth
# behaviour.  For those who are curious, invoke this script with
# --cong cubic and see what happens...
# sysctl -a | grep cong should list some interesting parameters.
parser.add_argument('--cong',
                    help="Congestion control algorithm to use",
                    default="reno")

# Expt parameters
args = parser.parse_args()


class BBTopo(Topo):
    "Simple topology for bufferbloat experiment."

    def build(self, n=2):
        # Here are two hosts
        hosts = []
        for i in range(1, n+1):
            hosts.append(self.addHost('h%d' % (i)))

        # Here I have created a switch.  If you change its name, its
        # interface names will change from s0-eth1 to newname-eth1.
        switch = self.addSwitch('s0')

        h1, h2 = hosts

        h1_bw = args.bw_host
        h2_bw = args.bw_net
        link_delay = args.delay
        max_qsize = args.maxq

        self.addLink(h1, switch, bw=h1_bw, delay=link_delay,
                     max_queue_size=max_qsize)
        self.addLink(h2, switch, bw=h2_bw, delay=link_delay,
                     max_queue_size=max_qsize)


# Simple wrappers around monitoring utilities.  You are welcome to
# contribute neatly written (using classes) monitoring scripts for
# Mininet!

# tcp_probe is a kernel module which records cwnd over time. In linux >= 4.16
# it has been replaced by the tcp:tcp_probe kernel tracepoint.
def start_tcpprobe(outfile="cwnd.txt"):
    os.system("rmmod tcp_probe; modprobe tcp_probe full=1;")
    Popen("cat /proc/net/tcpprobe > %s/%s" % (args.dir, outfile),
          shell=True)


def stop_tcpprobe():
    Popen("killall -9 cat", shell=True).wait()


def start_qmon(iface, interval_sec=0.1, outfile="q.txt"):
    monitor = Process(target=monitor_qlen,
                      args=(iface, interval_sec, outfile))
    monitor.start()
    return monitor


def start_iperf(net):
    h2 = net.get('h2')
    print("Starting iperf server...")
    # For those who are curious about the -w 16m parameter, it ensures
    # that the TCP flow is not receiver window limited.  If it is,
    # there is a chance that the router buffer may not get filled up.
    server = h2.popen("iperf -s -w 16m")
    # Get CWND through options on h1
    h1 = net.get("h1")

    # DONE TODO: Start the iperf client on h1.  Ensure that you create a long lived TCP flow. You may need to redirect iperf's stdout to avoid blocking.
    client = h1.popen("iperf --client {}".format(h2.IP()))


def start_webserver(net):
    h1 = net.get('h1')
    proc = h1.popen("python http/webserver.py", shell=True)
    sleep(1)
    return [proc]


def start_ping(net):
    # matter?)  Measure RTTs every 0.1 second.  Read the ping man page
    # to see how to do this.

    # Hint: Use host.popen(cmd, shell=True).  If you pass shell=True
    # to popen, you can redirect cmd's output using shell syntax.
    # i.e. ping ... > /path/to/ping.txt
    # Note that if the command prints out a lot of text to stdout, it will block
    # until stdout is read. You can avoid this by runnning popen.communicate() or
    # redirecting stdout
    h1 = net.get('h1')
    # popen = h1.popen("echo '' > %s/ping.txt" % (args.dir), shell=True)
    # i.e. ping ... > /path/to/ping.txt
    h2_ip = net.get('h2').IP()
    # DONE TODO: Start a ping train from h1 to h2 (or h2 to h1, does it
    h1.popen("ping -i 0.1 -w {1} {0}> {2}/ping.txt".format(h2_ip, args.time, args.dir), shell=True)


def bufferbloat():
    if not os.path.exists(args.dir):
        os.makedirs(args.dir)
    os.system("sysctl -w net.ipv4.tcp_congestion_control=%s" % args.cong)

    # Cleanup any leftovers from previous mininet runs
    cleanup()

    topo = BBTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    # This dumps the topology and how nodes are interconnected through
    # links.
    dumpNodeConnections(net.hosts)
    # This performs a basic all pairs ping test.
    net.pingAll()

    # Start all the monitoring processes
    start_tcpprobe("cwnd.txt")
    start_ping(net)

    # DONE TODO: Start monitoring the queue sizes.  Since the switch I
    # created is "s0", I monitor one of the interfaces.  Which
    # interface?  The interface numbering starts with 1 and increases.
    # Depending on the order you add links to your network, this
    # number may be 1 or 2.  Ensure you use the correct number.
    #
    qmon = start_qmon(iface='s0-eth2',
                     outfile='%s/q.txt' % (args.dir))

    # DONE TODO: Start iperf, webservers, etc.
    start_iperf(net)
    start_webserver(net)
    start_ping(net)

    # Hint: The command below invokes a CLI which you can use to
    # debug.  It allows you to run arbitrary commands inside your
    # emulated hosts h1 and h2.
    #
    # CLI(net)

    # DONE TODO: measure the time it takes to complete webpage transfer
    # from h1 to h2 (say) 3 times.  Hint: check what the following
    # command does: curl -o /dev/null -s -w %{time_total} google.com
    # Now use the curl command to fetch webpage from the webserver you
    # spawned on host h1 (not from google!)
    # Hint: have a separate function to do this and you may find the
    # loop below useful.
    times = webpage_transfer_time(net)

    # DONE TODO: compute average (and standard deviation) of the fetch
    std = helper.stdev(times)
    avg = helper.avg(times)
    
    print("standard deviation: {}\n".format(std))
    print("average: {}\n".format(avg))

    # times.  You don't need to plot them.  Just note it in your
    # README and explain.

    stop_tcpprobe()
    if qmon is not None:
        qmon.terminate()
    net.stop()
    # Ensure that all processes you create within Mininet are killed.
    # Sometimes they require manual killing.
    Popen("pgrep -f webserver.py | xargs kill -9", shell=True).wait()


def webpage_transfer_time(net):
    '''
    curl -o <file_path> -s -w %{time_total} h1

     Time appears on stdout we want to write it to a file 

    '''
     # DONE TODO: measure the time it takes to complete webpage transfer
    start_time = time()
    h1 = net.get('h1')
    h2 = net.get('h2')
    # TODO ensure that this command spits shit out on stdout
    cmd = "curl -o ./http/index.html -s -w %{time_total} " + h1.IP()
    times = []
    while True:
        # run the curl three times 
        for _ in range(3):
            process = h2.popen(cmd)
            process_time = process.stdout.read()
            process_time = float(process_time)
            times.append(process_time)
        # wait five seconds
        sleep(5) #This can stay
        now = time()
        delta = now - start_time 
        if delta > args.time: #stop after 100s
            break
        print ("%.1fs left..." % (args.time - delta))
    assert(len(time) == 60)
    return times

if __name__ == "__main__":
    bufferbloat()
