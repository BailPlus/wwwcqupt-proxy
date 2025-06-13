from flask import Flask

class Stopper(Flask):
	def __init__(self):
		super().__init__(__name__)
		self.before_request(self.main)
	@staticmethod
	def main():
		return '网站升级中，请稍后访问。谢谢合作！'

if __name__ == '__main__':
	Stopper().run(host='0.0.0.0',port=80)
