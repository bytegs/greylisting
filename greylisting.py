import sys, time, os
import syslog, traceback
#import MySQLdb
import ConfigParser, os
import datetime, time
import MySQLdb as mdb
import re

debug = 1

def syslog_traceback():
	lines = traceback.format_exception (sys.exc_type, sys.exc_value, sys.exc_traceback)
	for i in lines:
		print i
		syslog.syslog(i)
	sys.exit(1)

def printdebug(msg):
	print msg
	if debug:
		syslog.syslog(syslog.LOG_DEBUG, msg)

def pLog(msg):
	f = open("/tmp/greylisting.txt", "a")
	d = datetime.datetime.now()
	f.write("[%s] %s \r\n" % (d.strftime("%y-%m-%d %H:%M:%S"), msg))

class Handler:
	def __init__ (self):
		self.lines = {}
		config = ConfigParser.RawConfigParser()
		config.read('defaults.cfg')
		try:
			self.con = mdb.connect(config.get('MYSQL', 'host'), config.get('MYSQL', 'user'), config.get('MYSQL', 'pass'), config.get('MYSQL', 'db'));
			self.cur = self.con.cursor()
		except:
			pLog("FATAL!!! MYSQL Connection cant create, can`t run without MYSQL")
			pLog(str(sys.exc_info()))
			sys.exit()
			#todo: stuff
	def addLine(self, line):
		try:
			key, value = line.split('=',1)
			self.lines[key[:512]] = value[:512]
		except ValueError:
			printdebug("Unknown Input: " + k[:100])

	def details(self):
		address = ""
		sender = ""
		recipient = ""
		try:
			address = self.lines['client_address']
		except KeyError:
			pass
		try:
			sender = self.lines['sender']
		except KeyError:
			pass
		try:
			recipient = self.lines['recipient']
		except KeyError:
			pass
		return address,sender,recipient

	def getTime(self):
		adress,sender,recipient = self.details()
		self.cur.execute("SELECT * FROM `graylistingRule` ORDER BY `graylistingRule`.`prio` ASC")
		chains = self.cur.fetchall()
		for rule in chains:
			if rule[2] != None and re.match(rule[2], recipient) is not None:
				pLog("Match: "+rule[2])
				return rule[3];
		return 1000*1000;
	def addConnection(self):
		adress,sender,recipient = self.details()
		sql = 'SELECT `id` FROM `graylistingConnections` WHERE `sender` = "%s" AND `recipient` = "%s" AND `senderIp` = "%s"' % (sender, recipient, adress);
		self.cur.execute(sql)
		chains = self.cur.fetchone()
		if chains == None:
			sql = 'INSERT INTO `graylistingConnections`(`sender`, `recipient`, `senderIp`, `firstConnect`, `lastConnect`) VALUES ("%s", "%s", "%s", NOW(), NOW())' % (sender, recipient, adress)
			self.cur.execute(sql)
			self.con.commit()
		else:
			sql = 'UPDATE `graylistingConnections` SET `lastConnect`=NOW() WHERE `id` = %i' % chains[0]
			self.cur.execute(sql)
			self.con.commit()

	def firstConnectionSecounds(self):
		adress,sender,recipient = self.details()
		sql = 'SELECT UNIX_TIMESTAMP(`firstConnect`) FROM `graylistingConnections` WHERE `sender` = "%s" AND `recipient` = "%s" AND `senderIp` = "%s"' % (sender, recipient, adress);
		self.cur.execute(sql)
		chains = self.cur.fetchone()
		return chains[0]



syslog.openlog('smtpd-policy.py['+str(os.getpid())+']',0,syslog.LOG_MAIL)

pLog("Get Mail")
try:
	handler = Handler()
	while (1):
		k = sys.stdin.readline()
		if k:
			k = k.rstrip()
		else:
			pLog("EOF at stdin input")
			break

		if k:
			handler.addLine(k)
		else:
			# empty input line - we have to make a decision
			handler.addConnection();
			graysecounds = handler.getTime()
			pLog("Graylisting Time: %i" % graysecounds)
			firstConnect = handler.firstConnectionSecounds()
			currentTime = int(time.time())
			pLog("First Connection Time: %i" % (currentTime-firstConnect))
			#pLog(graysecounds);
			if(firstConnect + graysecounds < currentTime):
				pLog("Return: donno")
				print("donno");
			else:
				pLog("Return: defer_if_permit Greylisted for a while, try again later.")
				print("defer_if_permit Greylisted for a while, try again later.");

			#action = handler.get_policy()
			#printdebug('Action:'+action)

			#print("action=%s\n" % (action,))

			sys.stdout.flush()
			#info.cleanup()

except SystemExit:
    syslog_traceback()
except KeyboardInterrupt:
    syslog_traceback()
except:
	pLog("ERROR")
	syslog_traceback()
