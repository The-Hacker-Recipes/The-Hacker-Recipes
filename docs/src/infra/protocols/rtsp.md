---
authors: ShutdownRepo, Tednoob17
category: infra
---

# 🛠️ RTSP

## Theory
Real-Time Streaming Protocol also know as RTSP is a network control protocol designed for controls streaming media systems. The protocol facilitates the creation and management of media sessions between endpoints.
The default RTSP control port is 554 (commonly over TCP). Media usually streams via RTP over UDP on negotiated ports. Some servers also use 8554 as a non-standard alternative.

## Basic usage
Connect to an RTSP service
We can use various various tool to connect to a RTSP service like media server, ip cameras and video surveillance or media player and client. For that we can use command-line tools and a couple of handy applications.

The key to unlocking an RTSP stream is its URL. These URLs typically follow a predictable format:

```bash
rtsp://[username]:[password]@[ip_address]:[port]/[path_to_stream]
```
- `rtsp://` : The protocol, clearly stating "Hey, this is an RTSP stream."  
- `[username]:[password]@` : Often optional, but required for authenticated streams (e.g., most IP cameras).  
- `[ip_address]` : The IP address or hostname of the device serving the stream (e.g., 192.168.1.42).  
- `[port]` : The RTSP port, usually 554 (often omitted if it's the default).  
Some devices use non-standard ports (e.g., 8554), support TLS as `rtsps://` (commonly TCP 322 or 8554), or require RTSP over TCP (interleaved). In VLC/FFmpeg you can force TCP (e.g., ffplay -rtsp_transport tcp ...).
- `[path_to_stream]` : The specific path on the device that identifies the stream (e.g., `/stream1` , `/live/ch0` , `/onvif/profile1/media.smp`).  
This is the part that varies wildly between manufacturers!

The tool most used for basic RTSP consumption will be VLC Media Player and, for the more CLI-inclined, FFmpeg.
### Graphical Way (VLC Media Player)

Follow these steps to connect to an RTSP service:

VLC is the Swiss Army knife of media. If it streams, VLC probably plays it. This is your quickest route to eyeball an RTSP feed.

Open **VLC** :
- Go to `Media` > `Open Network Stream`  (or `Ctrl+N` / `Cmd+N`).
In the "Please enter a network URL:" field, paste your RTSP URL.
- Example (Common IP Camera Default):
  `rtsp://admin:password@192.168.1.10:554/stream1`
- Example (Public Test Stream):
  `rtsp://wowzaec2demo.streamlock.net/vod/mp4:BigBuckBunny_115k.mp4`
(This is a widely used public test stream if you don't have a camera handy.)
- Click Play.

### The Command-Line Way (FFmpeg)

For those who live in the terminal, ffmpeg is your friend. It's incredibly powerful for processing media and to simply view an RTSP stream (though it usually sends it to a player like FFplay or pipes it elsewhere).

First, ensure you have FFmpeg installed. If you're on Linux, it's often sudo apt install ffmpeg or sudo dnf install ffmpeg. On macOS, brew install ffmpeg. Windows users, grab a static build.

To view an RTSP stream with ffplay (which comes with FFmpeg):

```bash
ffplay rtsp://wowzaec2demo.streamlock.net/vod/mp4:BigBuckBunny_115k.mp4
```

Or, if you want to test the connection and see stream information without a GUI:

```bash
ffmpeg -i rtsp://admin:password@192.168.1.10:554/stream1 -c copy -f null -
```

What's happening here?:
- `-i` : Specifies the input source (your RTSP URL).
- `-c copy` : Tells FFmpeg to just copy the video/audio streams without re-encoding.
- `-f null -` : Sends the output to a "null" destination, essentially discarding it. We're just interested in the connection and the information FFmpeg reports.

You'll see a lot of verbose output: connection attempts, stream details (codec, resolution, FPS), and potentially error messages if it fails.

## Footprinting and Passive Recon

### Information Gathering

- OSINT (Open-Source Intelligence):

:::tabs

=== Google dork
The dig utility performs DNS lookups and displays responses from name servers.

```bash
# publicly exposed camera feeds, security system

inurl:/view.shtml intitle:"Live View" or inurl:/CGI_Stream.cgi
```

=== Shodan.io
The search engine for the Internet of Things

```bash
# find publicly exposed RTSP services

port:554 or rtsp
```
:::


## Enumeration


- Port Scanning (Nmap):

You can gently probe the network for active RTSP services.

```bash
# -sV: Attempts to determine service versions, which can often reveal camera manufacturers and models.
nmap -p 544  -sV "$TARGET_IP"
# --script=rtsp-methods: This script connects to the RTSP service and issues an OPTIONS * request to determine which RTSP methods the server supports.
nmap -p 554 --script=rtsp-methods "$TARGET_IP"
# --script=rtsp-url-brute: This is a more intrusive but often highly effective script.
nmap -p 554 --script=rtsp-url-brute "sq$TARGET_IP"
```

- Banner Grabbing
For a quick, raw look at the service, you can try connecting directly and sending an OPTIONS request.

```bash
echo -e "OPTIONS rtsp://$TARGET_IP:554/ RTSP/1.0\nCSeq: 1\n\n" | nc -nv $TARGET_IP 554
```

## Attack Vectors

- Default and Weak Credentials:
This is the most common and impactful attack vector. Many IP cameras ship with widely known default usernames and passwords, or users set easily guessable ones.

```bash
hydra -L userlist.txt -P passlist.txt rtsp://$TARGET_IP -s 554 -t 10
# -t for threads
# userlist.txt: Common defaults (admin, root, user).
# passlist.txt: Common defaults (admin, 12345, password, blank lines), plus dictionary words.
```
- Anonymous/Unauthenticated Access:
 A shockingly common misconfiguration. Some cameras are set to allow anyone to view the stream if they know the RTSP URL, without any authentication.
```bash
vlc rtsp://$TARGET_IP:$PORT/$STREAM_PATH
```
- Unencrypted Streams: RTSP, in its basic form, does not encrypt the actual video/audio data (RTP). Even if the RTSP control channel is authenticated, the media payload might be sent in the clear.


## Post-Exploitation: Beyond the Stream

RTSP devices offer unique opportunities for persistence and deeper network pivots.
- Live Stream Recording: Use FFmpeg to record the live stream for detailed post-operation analysis. This is your digital evidence locker.

```bash
ffmpeg -i rtsp://$USER:$PASS@$IP:$PORT/$PATH -map 0:v -c:v copy -t 00:30:00 recorded_intel42.mp4
```


## Ressources
* [wireshark rtsp](https://wiki.wireshark.org/RTSP)
* [RTSP wikipedia](https://en.wikipedia.org/wiki/Real-Time_Streaming_Protocol)
* [n0a110w github](https://n0a110w.github.io/notes/security-stuff/services/rtsp.html)
* [Victor Mendonça](https://blog.victormendonca.com/2018/02/09/how-to-scan-for-rtsp-urls)
* [exploit notes](https://exploit-notes.hdks.org/exploit/network/protocol/rtsp-pentesting/)
