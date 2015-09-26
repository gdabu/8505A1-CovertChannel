from scapy.all import *

craftedPkt = IP()/TCP();

craftedPkt["TCP"].dport = 80;
craftedPkt["IP"].dst = "192.168.0.17";
randPort = 25088;

secret_message = raw_input("Enter your secret message: ")
print "Secret Message: " + secret_message

secret_messageB = [bin(ord(ch))[2:].zfill(8) for ch in secret_message]

print "Secret Message in Bytes: " + str(secret_messageB)

secret_messageDecoded = "";
for b1 in secret_messageB:
        secret_messageDecoded += str(chr(int(b1, 2)))

print "Decoded Message: " + secret_messageDecoded

# < 25088 <
print randPort;
print str(craftedPkt["TCP"].sport);
craftedPkt.show()

for b1 in secret_messageB:
    for b2 in b1:
        if (b2 == '0'):
            randPort = random.randint(1025, 25087);
            craftedPkt["TCP"].sport = randPort;
        else:
            randPort = random.randint(25089, 49151);
            craftedPkt["TCP"].sport = randPort;
        send(craftedPkt)
