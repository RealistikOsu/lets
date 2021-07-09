import tornado.gen
import tornado.web

from common.web import requestsManager


class handler(requestsManager.asyncRequestHandler):
	@tornado.web.asynchronous
	@tornado.gen.engine
	def asyncGet(self):
		print("404: {}".format(self.request.uri))
		self.redirect("https://ussr.pl/"+self.request.uri)
