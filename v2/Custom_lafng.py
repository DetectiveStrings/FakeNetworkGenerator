import scapy.all as sc 
import Freq_use as Fuse



#var

##################################################################################################################################################################################################################
################################################################################### Datalink Layer ###############################################################################################################
##################################################################################################################################################################################################################

#################################################################################################### linux cooked capture 16 bytes   used by wireshark sll So its not a big problem 
def LCP(pcaket_type = 1 , Link_Layer_add_type = 1 , Link_Layer_add_len = 6 , src_Mac = '88:88:88:88:88:88', protocal = 3 ):
    pcaket_type 		=	struct.pack('>h' , (pcaket_type))  					# 2 bytes  
    Link_Layer_add_type 	=	struct.pack('>h' , (Link_Layer_add_type))     				# 2 bytes 
    Link_Layer_add_len 	=	struct.pack('>h' , (Link_Layer_add_len))       				# 2 bytes 
    src_Mac			=	Fuse.Mac2Hex(src_Mac) 							# 6 bytes 
    Unused 			=	b'\x00\x00'								# 2 bytes
    protocal 		=	struct.pack('>h' , (protocal)) 						# 2 bytes 
    Padding			= 	b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'	## any padding will be attached to this section  
    LCP = pcaket_type +Link_Layer_add_type+Link_Layer_add_len+src_Mac+Unused+protocal
    return(LCP)

################################################################################################### Ether 
def ETH(Eth_Dest_Hw_Addr= '00:00:00:00:00:00' , Eth_Src_Hw_Addr = '88:88:88:88:88:88' , Eth_Type = 3 ):
    Eth_Dest_Hw_Addr= Fuse.Mac2Hex(Eth_Dest_Hw_Addr)                                # 6 bytes 
    Eth_Src_Hw_Addr = Fuse.Mac2Hex(Eth_Src_Hw_Addr)                                 # 6 bytes 
    Eth_Type        = struct.pack('>h' , (Eth_Type))                                # 2 bytes
    Ether           = Eth_Dest_Hw_Addr + Eth_Src_Hw_Addr + Eth_Type
    return(Ether)


##################################################################################################################################################################################################################
###################################################################################### Internet Layer ############################################################################################################
##################################################################################################################################################################################################################

################################################################################################### ARP 28 byte
def ARP(Ar_Hware_Type= 1 , Protocol_Type= 0x800  , Opcode=1 ,Sender_Hw_Mac='88:88:88:88:88:88', Sender_Ip_Add='44.44.44.44' ,Target_Mac='00:00:00:00:00:00' ,Target_Ip_Add='55.55.55.55' ):
    Ar_Hware_Type 	= struct.pack('>H' , (Ar_Hware_Type))  		            # 2 bytes
    Protocol_Type 	= struct.pack('>H' , (Protocol_Type)) 		            # 2 bytes 
    Ar_Hware_Size 	= '\x06'.encode('utf-8')		                    # 1 byte
    Protocol_Size 	= '\x04'.encode('utf-8')		                    # 1 byte 
    Opcode		= struct.pack('>H' , (Opcode))  		            # 2 bytes 
    Sender_Hw_Mac	= Fuse.Mac2Hex(Sender_Hw_Mac)			            # 6 bytes 
    Sender_Ip_Add	= struct.pack('>I' , Fuse.ip2int(Sender_Ip_Add))	    # 4 bytes
    Target_Mac	= Fuse.Mac2Hex(Target_Mac)				            # 6 bytes 
    Target_Ip_Add	= struct.pack('>I' , Fuse.ip2int(Target_Ip_Add)) 	    # 4 bytes 	
    Arp = Ar_Hware_Type + Protocol_Type + Ar_Hware_Size + Protocol_Size + Opcode + Sender_Hw_Mac + Sender_Ip_Add + Target_Mac + Target_Ip_Add 
    return(Arp)

################################################################################################### IP 
def IP(version = 4 , lenth = 17 ):
    version_and_len     =  bytes( chr(ord(str(version))+ lenth)  , encoding = 'utf-8')                        # 2 bytes
    
  
    nulB = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    
    ip = version_and_len + nulB
    return ip


#lc = LCP(protocal = 0x806)
#ar = ARP(Protocol_Type = 0x800)
#et = ETH(Eth_Type = 0x806)


#for i in range(256):
#	xx = str(hex(i))[2:] 
#	if(len(xx) < 2  ):
#		xx = '0'+xx
#	dstmac = '00:e2:69:0f:9e:09'
	#mac = "00:00:00:00:00:"+xx
	#ar = ARP(Opcode = 2 , Sender_Hw_Mac='00:e2:69:0f:9e:09'  , Sender_Ip_Add ='10.5.232.167' , Target_Ip_Add = '10.5.239.171' , Target_Mac='e8:2a:44:f3:ec:6b')
#	ar = ARP(Opcode = 1 , Sender_Hw_Mac='e8:2a:44:f3:ec:6b'  , Sender_Ip_Add ='10.5.232.167' , Target_Ip_Add = '10.5.0.1' , Target_Mac='00:00:00:00:00:00')
	#et = ETH(Eth_Src_Hw_Addr = '00:e2:69:0f:9e:09', Eth_Dest_Hw_Addr='e8:2a:44:f3:ec:6b' , Eth_Type = 0x806)
et = ETH(Eth_Src_Hw_Addr = 'e8:2a:44:f3:ec:6b', Eth_Dest_Hw_Addr='ff:ff:ff:ff:ff:ff' , Eth_Type = 0x800)

for i in range(10):
    ip = IP()
    send = et+ip
#sc.send(sc.IP(),iface='vmnet15' )

    sc.sendp(send , iface='vmnet1')

print(send)
#print(Mac2Hex("19:12:45:78:84:12"))
