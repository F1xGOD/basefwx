from setuptools import setup, find_packages

setup(
	name='basefwx',
	version='2.9',
	packages=find_packages(),
	install_requires = ["cryptography"],
	description = 'With BaseFWX you can encode securely!',
	authors = [{"name":"F1xGOD","email":"f1xgodim@gmail.com"}],
	readme = "README.md"
)
