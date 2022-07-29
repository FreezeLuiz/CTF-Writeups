# Sector443 CTF 2020: IoT - CAN_Y0u_GetInto_MyC@r

## Description:

...No picture of the description :'(

From the description, we got a `pcap` file and a silly drawn graph where one axis was the `speed` of a car and the other axis was `time`:

![img](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Misc/images/sector443/iot-graph.PNG "Silly graph")

Nevertheless, our goal is to catch the hex identifier of the motor's ECU.

## Recon and Analysis:

Opening the `pcap` file, in wireshark, we are greeted with the `CAN` protocol; which is used in modern vehicles to allow the ECU (Electronic Control Unit) to communicate with other devices.

![img](https://raw.githubusercontent.com/FreezeLuiz/CTF-Writeups/master/Misc/images/sector443/iot-pcap.PNG "bruh!")

I tried searching on the `CAN` protocol but there were a lot of information, and the CTF only had 1 hour left. So, I starting thinking simplier. If they want the identifier of the motor, then the payload must increase with time (like we see from the kiddie graph)...

Which bring me to the solution.

## Solution:

My solution was to sort the payload (ascending order) and look for the payload that increases periodically with time (just like we see in the speedometer of any car) and try that identifier as the flag:

```
...
39396	9.974969024			CAN	32	STD: 0x000007d2   00 00 00 00 31 14 00
39458	9.986992444			CAN	32	STD: 0x000007d2   00 00 00 00 31 26 00
39499	9.999096395			CAN	32	STD: 0x000007d2   00 00 00 00 31 39 00
39541	10.011048101			CAN	32	STD: 0x000007d2   00 00 00 00 31 4b 00
39591	10.023050642			CAN	32	STD: 0x000007d2   00 00 00 00 31 5d 00
```

When I try `S443{0x7d2}` as the flag, it gets accepted!
