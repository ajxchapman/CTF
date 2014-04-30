# Submission for B-Sides London Mission 3: The Geo-Cracker (https://www.securitybsides.org.uk/challenge3.html)
Alex J Chapman

C / ASM implementation of a solution requiring no external dependencies or libraries. This solution aims for over 95% accuracy (for the UK coordinate set) in the fastest time possible without relying on 3rd party or system libraries. Implementation includes pure code based base64 stream decoding and state machine byte analysis to identify a possible decryption key.

For reference compiling should be done with the following command:
gcc -s -nostdlib -o decrypt decrypt.c

Examples:
pi@raspberrypi ~ $ ./decrypt UwQfSRgeHxlEC1hCQUgfGkkdCFgKEBQYSxtAQV1UGB1IHRBHFgIAAEodSk9JSBwCSRoBVAoJBwZVFkBFW1ALDl0LDUQPDxYbRxRFRkZeCQ9HEhJFEBITCkMSX19bUwcMXB0dTAQCBwtYDFdPUl4SFUcVFkoeCggJQxdCQUhHEw1GEglfCg8JD1IRR0tVVAIFWgoLQhUPCA5YAlVZSUQWCl0MCF0IDRYOXhNITklBFR9ZDQtAExcQHEwbVE1OWAsLXwkFUBYUEwhVAFVWVl8RDlgXE0IdHRocWA5YQkdGFRVGEwpCFQ8LCV0GVVU=

51.397573,-4.880270
    
pi@raspberrypi ~ $ ./decrypt V1sXExVEEEBCCxcRDFhdXAcGUUdGH1QEBFJRVV8SCAlFSR4dHUgVVFAMExYRRUZEFgNMSVMBVg8JXVlNSxgBAFJSCQ8KRw9dQhcWFhRARVUCDEBDQhRAGRtSTkhVAQ8KW1cFExJLAFdUCAoMDEFGWAIPW1lYCUwYG1BRXFsLCg5AVAUdGk8fRkERAAEGSUtCGRJCQFgIQxsTQ0VJSgsJCUVJGR0fTx1QUBsdEBFBR04MAFVNTBRBGRBEWUBCDQ4HVFkOCx9LFllaCgsKDlhDXg8YTkpLEkQTAlJWTE4aGh5IRggTEl0OWF8JCgs=
    
52.109901,-3.004152
    
pi@raspberrypi ~ $ ./decrypt AAYYGRseGxgeUVdISRweT0lCUlZRSE9ITRcVFAteQhAXFRcfGwwNAx1PT09NEBpXUk5JQExDRUdXAQEeGkhNHxsaBhobAgUEB1ZTWkkYHVJfXFtcXVxEXlsWExMZS0EXAgUDHBkZFBsdT1VJSwEHVFVVVVNHRkJbXAsJCAJTTQEEGBofGh8aHg5YXENFGR9PTUlVSU5XVlNSAw0PHE1JBgQAAwMADxcNCEVEQUIVE0JXUFBPTk9OQEQRCxcUXl0EAgUNDRkbGAEIWVtdWw4QXFtHT0xPQU1DUwUAHxlNSBAVEAwNFxkZHR9OTw==
    
56.767313,-5.363238
