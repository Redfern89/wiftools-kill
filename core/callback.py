class Callback:
	def __init__(self):
		pass

	def setCallback(self, name, func):
		if hasattr(self, name):
			setattr(self, name, func)

	def detachCallback(self, name, func):
		if hasattr(self, name):
			setattr(self, name, None)