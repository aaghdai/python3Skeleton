# Copyright 2017 New York University
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse

from hashlib import sha256
from scapy.all import *

class G(object):
    previousTimeStamps = {}

def analyzePacket(packet):
    if TCP in packet:
        L4 = packet[TCP]
    elif UDP in packet:
        L4 = packet[UDP]
    else:
        return

    fId = sha256("{} {} {} {} {}".format(
            packet[IP].src,
            packet[IP].dst,
            L4.sport,
            L4.dport,
            packet[IP].proto).encode()
       ).hexdigest()

    if fId not in G.previousTimeStamps:
        G.previousTimeStamps[fId] = packet.time

    print(
            fId,
            packet.time - G.previousTimeStamps[fId], 
            len(packet),
            packet[IP].src,
            packet[IP].dst,
            L4.sport,
            L4.dport,
        )

    G.previousTimeStamps[fId] = packet.time

def readPcap(pcapFile,              # Input pcap file
        count,                      # Number of packets to be read from pcap file
        detectFlows,                # ID flows if True
        detectFlowlets,             # ID flowslets if True
        flowletThreshold,           # Flowlet silent timeout threshold in seconds
    ):
    sniff(offline = pcapFile,
            count = count,
            store = False,
            prn = analyzePacket)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help = "Input pcap file", type = str)
    parser.add_argument("-f", "--with-flow-ids", action = "store_true",
            help = "Whether flow IDs are shown at output") 
    parser.add_argument("-F", "--with-flowlet-ids", action = "store_true",
            help = "Whether flowlet IDs are shown at output") 
    parser.add_argument("-t", "--threshold", type = float,
            help = "Flowlet silent timeout in seconds", default = 10e-3)
    parser.add_argument("-c", "--count", type = int,
            help = "Number of packets to be read from the specified pcap file",
            default = 0)
    args = parser.parse_args()
    readPcap(pcapFile = args.input,
            count = args.count,
            detectFlows = args.with_flow_ids,
            detectFlowlets = args.with_flowlet_ids,
            flowletThreshold = args.threshold)
