import SimpleHTTPServer
import SocketServer
import httpagentparser
import sys
import json
import datetime
from xml.dom.minidom import parse, parseString
import time
import os.path
import argparse

parser = argparse.ArgumentParser()

parser.add_argument("-m", "--mode", help="Learning Mode( -m learning ) or Protect Mode ( -m protect)")
parser.add_argument("-p","--port",help="Port")
args = parser.parse_args()


class MyTCPHandler(SocketServer.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    ip = ""
    userAgent = ""
    data = ""
    time=time
    mode = args.mode    

	#Fonction trouve sur internet. Finalement je ne l'utilise pour ne pas perdre trop de temps dans le traitement de l'information.
	# A la base, je voulais que les informations soient affiches dans l'ordre inverse de l'ordre chronologique
    def writeBeginingOfFile(self,file,string):
    	# read the current contents of the file
		f = open(file)
		text = f.read()
		f.close()
		# open the file again for writing
		f = open(file, 'w')
		f.write(string)
		# write the original contents
		f.write(text)
		f.close()
	
	#Calcul la vitesse (requete/seconde) a partir des dernieres connexion (10 max)
    def calculReqSpeed(self,lastCon):
		i = len(lastCon)
		a = 0
		tableauVitInstant = []
		sommeVitInstant = 0
		for a in range (0,i-1):
			tableauVitInstant.append(self.calculInstantReqSpeed(lastCon[a],lastCon[a+1]))
			sommeVitInstant += tableauVitInstant[a]

		return sommeVitInstant/i

	#Calcul de la vitesse "instantane"
    def calculInstantReqSpeed(self,t1,t2):
		return 2/(t1-t2)

    def isStringInFile(self,file,string):
		rep = False
		f = open(file, 'r')
		lines = f.readlines()
   		f.close()
		line = ""
		for line in lines:
			if string in line:
				rep = True
				break
		return rep

    def checkIfMoreThanTenConnexion(self):
		rep = False
		f = open("log/"+self.ip+".txt", 'r')
		nOfLine = 0
		for line in f:
			nOfLine += 1
			if nOfLine > 10:
				rep = True
				break
		return rep

    def isClientSuspicious(self):
		speed = 0
		rep = False
		if self.checkExistingFile("log/"+self.ip+".txt") and self.checkIfMoreThanTenConnexion():
			listLastConnexion = self.fetchLastConnexion()
			speed = self.calculReqSpeed(listLastConnexion)
			print "Speed :"+str(speed)+"req/s\n"
			if speed > 100:
				rep = True
		return rep

    def fetchLastConnexion(self):
    	i = 0
    	res = []
    	for line in reversed(list(open("log/"+self.ip+".txt"))):
			if i != 10:
				res.append(float(line.strip(self.ip+":\n")))
				i += 1
			else:
				break

        return res

    def writeInExistingFile(self,file,string):
    	f = open(file,'a')
    	f.write(string)
    	f.close
	

    def writeInLog(self):
	  	nbPrecis = "%.10f" % float(self.time)
		string = ""
		string = self.ip+":"+str(nbPrecis)+"\n"
		if self.checkExistingFile("log/"+self.ip+".txt"):
			self.writeInExistingFile("log/"+self.ip+".txt",string)
		else:
			self.writeInNewFile("log/"+self.ip+".txt",string)

    def writeInNewFile(self,file,string):
	f = open(file,'w')
	f.write(string)
	f.close

    def checkExistingFile(self,file):
		rep = False
		if os.path.isfile(file):
			rep = True
		return rep

    def writeInBlacklist(self,string):
    	if not self.isStringInFile("blacklist.txt",string):
			finalString = ""
			finalString = self.ip+" - "+string+"\n"
			self.writeInExistingFile("blacklist.txt",finalString)
    
    def refuseConnexion(self):
		print("Connexion refused")
		self.request.sendall("Degages")

    def fetchUserAgent(self,item):
		self.userAgent= item.strip("User-Agent:")
		self.userAgent = dict(httpagentparser.detect(self.userAgent))
    
    def isItWhiteRequest(self):
		rep = False
		if not self.data:
			rep=True
		return rep

    def isThereUserAgent(self):
		rep = False
		for item in self.data.split("\n"):
			if "User-Agent" in item:
				self.fetchUserAgent(item)			
				rep = True
				print("Client has User Agent")
		return rep

    def isThereUnauthorizedUA(self):
		rep = True
		print self.userAgent
		platform = self.userAgent['platform']
	
		#if format(platform['version']) & format(platform['name']):
		if platform['name'] is not None:
			print("The client has authorized User Agent\r\n")
			rep = False
		
		return rep

    def handle(self):
	
		self.data = self.request.recv(1024).strip()
		self.ip = self.client_address[0]
		self.time = time.time()
		print("\r\n")
		print str(datetime.datetime.fromtimestamp(self.time))
		print "Here is the HTTP header :"+self.data	
		
		
		# self.request = TCP socket connecte au client
		print "il est blackliste :"+str(self.isStringInFile("blacklist.txt",self.ip))
		if self.isStringInFile("blacklist.txt",self.ip) == True and self.mode == "protect":
			print("The ip "+self.ip+" is blacklisted")
			self.refuseConnexion()
		else:
			if self.isItWhiteRequest() == True:
				self.request.sendall("")
			else: 
				if self.isThereUserAgent() == False:
					string = "No User Agent "
					self.writeInBlacklist(string)
					if self.mode == "protect":
						self.refuseConnexion()
						print("**Scanner Detected** - No User Agent")
				elif self.isThereUnauthorizedUA():
					string="Unauthorized User Agent - UA: "+str(self.userAgent)
					self.writeInBlacklist(string)
					if self.mode == "protect":
						self.refuseConnexion()
						print("**Scanner Detected** - Unauthorized User Agent")
				elif self.isClientSuspicious():
					string = "Suspicious request Speed - UA: "+str(self.userAgent)
					self.writeInBlacklist(string)
					if self.mode == "protect":
						print("**Scanner Detected** - Suspicious request Speed")
						self.refuseConnexion()
				else:
					self.writeInLog()
					# Renvoie navigateur utilise + la requete HTTP
					self.request.sendall("Tu navigues avec "+self.userAgent["browser"]["name"]+"\r\n"+self.data.upper())


if __name__ == "__main__":
	HOST, PORT = "localhost", args.port
	print ("mode "+args.mode)
	print("Listen on port : "+PORT)
    	# Create the server, binding to localhost on port 9999
	server = SocketServer.TCPServer(("", int(PORT)), MyTCPHandler)

    	# Activate the server; this will keep running until you
    	# interrupt the program with Ctrl-C
	server.serve_forever()

