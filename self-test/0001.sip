v=0
o=LifeSize 1366021474 2 IN IP4 192.168.190.101
s=LifeSize SIP Call
i=LifeSize Icon_600/LS_RM3_1.1.0 (16)
c=IN IP4 192.168.190.101
b=CT:2500
t=0 0
m=audio 60022 RTP/AVP 113 123 122 121 9 0 8 101
a=rtpmap:113 MP4A-LATM/32000
a=fmtp:113 profile-level-id=2;object=2;bitrate=96000
a=rtpmap:123 G7221/32000
a=fmtp:123 bitrate=48000
a=rtpmap:122 G7221/32000
a=fmtp:122 bitrate=32000
a=rtpmap:121 G7221/32000
a=fmtp:121 bitrate=24000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
m=video 60024 RTP/AVP 96 97
b=TIAS:2500000
a=rtpmap:96 H264/90000
a=fmtp:96 profile-level-id=42802a;max-mbps=490000;max-fs=8192;packetization-mode=1
a=rtpmap:97 H263-1998/90000
a=fmtp:97 CIF4=1;CIF=1;QCIF=1
a=content:main
a=rtcp-fb:* ccm fir
a=rtcp-fb:* nack pli
a=rtcp-fb:* ccm tmmbr
m=application 60026 RTP/AVP 100
a=rtpmap:100 H224/4800
m=control 60028 RTP/AVP 96
b=TIAS:2500000
a=rtpmap:96 H264/90000
a=fmtp:96 profile-level-id=428029;max-mbps=245000;max-fs=8192;packetization-mode=1
a=label:3
a=rtcp-fb:* ccm fir
a=rtcp-fb:* nack pli
a=rtcp-fb:* ccm tmmbr
a=inactive
m=application 60032 TCP/BFCP *
a=floorctrl:c-only
a=setup:active
a=connection:new
