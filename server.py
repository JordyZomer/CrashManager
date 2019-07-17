from glob import glob
from optparse import OptionParser
from sys import exit
import tornado.ioloop
import tornado.web
import docker

OUTPUT = "./results/*.txt"

DEBUG_ON = False

def DEBUG(msg):
    if DEBUG_ON:
        print(msg)

class AsanLog:
    def __init__(self, data=None, fname=None, depth=5):
        self.data  = data
        self.depth = depth
        self.fname = fname
        self.stack = []
        self.dups  = []
        self.desc  = ""
	self.comp  = fname.split("/")[2].split('-')[0]
	self.iden  = fname.split("/")[2].replace(".txt", "")
        if self.data:
            self.get_description()
            self.get_stack_trace()
	    self.vuln  = self.desc.split(" ")[0] 

    
    def get_description(self):
        if not self.data:
            return ""
        data = self.data.splitlines()
        for line in data:
            if "ERROR:" in line:
                self.desc = line[line.find('Sanitizer:')+11:]
                break
        return self.desc

    def get_stack_trace(self):
        """Return a list of stack trace addresses"""
        if not self.data:
            return []

        if not self.has_stack_trace():
            self.desc = "No ASAN Stack"
            return []

        data = self.data.splitlines()
        while "#0" not in data[0]:
            data.pop(0)
        for x in range(0, self.depth):
            lno = "#%d" % x
            if lno not in data[0]:
                return self.stack
            addr = data[0].lstrip(' ').split(' ')[1]
            self.stack.append(addr)
            data.pop(0)
        return self.stack

    def has_stack_trace(self):
        """Return true if stack trace data is in self.data"""
        return "#0" in self.data and "#1" in self.data

    def compare_stack(self, log):
        """Return true if stack trace (up to depth) is equal between self and log."""
        if len(self.stack) != len(log.stack):
            return False
        
        for x in range(0, len(self.stack)):
            DEBUG("Stack Trace(%d): %s %s" % (x, self.stack[x], log.stack[x]))
            if self.stack[x] != log.stack[x]:
                return False
        return True

    def serialize(self):
        """Return - (String) comma separated stack trace"""
        if not self.stack:
            return ""
        return ','.join(self.stack)

def get_logs():
	files = glob(OUTPUT)
	logs = []

	for f in files:
		found_stack = False
		fd = open(f, 'r')
		new_log = AsanLog(fd.read(), fname=f, depth=5)
		fd.close()
		for log in logs:
		    if log.compare_stack(new_log):
			log.dups.append(f)
			found_stack = False
			break
		if not found_stack:
		    logs.append(new_log)
	return logs

class MainHandler(tornado.web.RequestHandler):
    def get(self):
	logs = get_logs()
	return self.render("index.html", logs=logs)

class CrashHandler(tornado.web.RequestHandler):
    def get(self):
	ident = self.get_argument("id")
	logs = get_logs()
	for log in logs:
		if log.iden == ident:
			with open(log.fname.replace("txt", "repro"),"rb") as repro:
				return self.render("crash.html", log=log, repro=repro.read())
	raise tornado.web.HTTPError(404)

class FuzzerHandler(tornado.web.RequestHandler):
    def get(self):
	dcker = docker.from_env()
	clients = dcker.containers.list()
	return self.render("fuzzers.html", clients=clients) 

class LogHandler(tornado.web.RequestHandler):
    def get(self):
	name = self.get_argument("id")
	count = self.get_argument("lines")
	if int(count) > 50:
		return self.write("lines too long")
	dcker = docker.from_env()
	container = dcker.containers.get(name)
	lines = []
	lines = container.logs(tail=int(count))

	return self.render("logs.html", lines=lines)


def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/crash", CrashHandler),
        (r"/fuzzers", FuzzerHandler),
        (r"/logs", LogHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(80)
    tornado.ioloop.IOLoop.current().start()
