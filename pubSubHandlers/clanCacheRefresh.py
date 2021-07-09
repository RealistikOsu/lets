from common.redis import generalPubSubHandler
from objects import glob

class handler(generalPubSubHandler.generalPubSubHandler):
	def __init__(self):
		super().__init__()
		self.structure = ""
		self.strict = False

	def handle(self, data):
		data = super().parseData(data)
		print(f"Clan Cache: Requested refresh fro user {data}")
		if data is None: return
		glob.clan_cache.cache_individual(int(data))
